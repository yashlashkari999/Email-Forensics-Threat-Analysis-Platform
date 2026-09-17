import reflex as rx
import asyncio
import json
import logging
import re
import sys
import dns.asyncresolver
import dns.exception
import dns.resolver
from app.states.evidence import Report, Finding, Factor


async def txt_check(name: str, query: str) -> Finding:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        answers = await asyncio.wait_for(
            resolver.resolve(query, "TXT"), timeout=4
        )
        records = [
            b"".join(answer.strings).decode("utf-8", "replace")
            for answer in answers
        ]
        return Finding(
            name=name,
            query=query,
            status="observed",
            records=records,
            detail="Live TXT response; not message authentication.",
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        logging.exception(f"Error: {e}")
        return Finding(
            name=name,
            query=query,
            status="absent",
            detail="No TXT record at this name.",
        )
    except Exception as e:
        logging.exception(f"Error: {e}")
        return Finding(
            name=name,
            query=query,
            status="unknown",
            detail=f"DNS unavailable ({type(e).__name__}); no negative conclusion.",
        )


async def check_domain(domain: str) -> Finding:
    process = None
    try:
        # A killable subprocess enforces a total deadline across checkdmarc's recursive lookups.
        script = "import checkdmarc,json,sys; r=checkdmarc.check_domains([sys.argv[1]],timeout=2); print(json.dumps(r[0] if isinstance(r,list) else r,default=str))"
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=12)
        if process.returncode != 0:
            return Finding(
                name="checkdmarc",
                query=domain,
                status="unknown",
                detail="Domain validator could not complete; independent TXT checks retained.",
            )
        data = json.loads(stdout)
        return Finding(
            name="checkdmarc",
            query=domain,
            status="completed",
            detail=json.dumps(
                {key: data.get(key, {}) for key in ("spf", "dmarc", "dnssec")},
                indent=2,
                ensure_ascii=True,
            ),
        )
    except Exception as e:
        logging.exception(f"Error: {e}")
        return Finding(
            name="checkdmarc",
            query=domain,
            status="unknown",
            detail=f"Validator unavailable ({type(e).__name__}); total deadline 12 seconds.",
        )
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.communicate()


def posture(finding: Finding, prefix: str) -> Finding:
    if finding.status == "unknown":
        return finding
    records = [
        r for r in finding.records if r.lower().startswith(prefix.lower())
    ]
    finding.records = records
    if not records:
        finding.status = "absent"
        finding.detail = "No matching policy found at the queried domain. Organizational fallback, if available, is shown separately by checkdmarc."
    elif len(records) > 1:
        finding.status = "invalid"
        finding.detail = "Multiple policy records; ambiguous configuration."
    else:
        finding.status = "published"
        finding.detail = "Policy published. Syntax/recursive validation is reported separately by checkdmarc; this is not a message-level pass."
    return finding


async def enrich(report: Report) -> Report:
    if not report.domain:
        report.dns = [
            Finding(
                name=n,
                status="unknown",
                detail="No unambiguous sender domain; DNS check skipped.",
            )
            for n in ("TXT", "SPF", "DMARC", "DKIM", "checkdmarc")
        ]
    else:
        names = [("TXT", report.domain), ("DMARC", f"_dmarc.{report.domain}")]
        selectors = ["default", "selector1", "selector2", "google", "k1"]
        for header in report.headers:
            if header.name.lower() == "dkim-signature":
                selector = re.search(
                    r"(?:^|;)\s*s=([a-zA-Z0-9_-]{1,63})\s*(?:;|$)", header.value
                )
                signing = re.search(r"(?:^|;)\s*d=([^;\s]+)", header.value)
                if (
                    selector
                    and signing
                    and signing.group(1).lower().rstrip(".") == report.domain
                ):
                    if selector.group(1) not in selectors:
                        selectors.append(selector.group(1))
        names.extend(
            (f"DKIM / {s}", f"{s}._domainkey.{report.domain}")
            for s in selectors[:8]
        )
        results = await asyncio.gather(
            *(txt_check(n, q) for n, q in names), check_domain(report.domain)
        )
        txt = results[0]
        spf = posture(
            Finding(
                name="SPF",
                query=report.domain,
                status=txt.status,
                records=list(txt.records),
                detail=txt.detail,
            ),
            "v=spf1",
        )
        dmarc = posture(results[1], "v=DMARC1")
        for finding in results[2:-1]:
            finding.detail = f"{finding.detail} Selector probe only: DKIM signature NOT verified. Absence is inconclusive."
        report.dns = [txt, spf, dmarc, *results[2:]]
    score_report(report)
    return report


def score_report(report: Report) -> None:
    spf = next(f for f in report.dns if f.name == "SPF")
    dmarc = next(f for f in report.dns if f.name == "DMARC")
    spf_points = 0
    if spf.status in ("absent", "invalid"):
        spf_points = 20
    elif spf.records and re.search(
        r"(?:^|\s)\+?all(?:\s|$)", spf.records[0], re.I
    ):
        spf_points = 20
    elif spf.records and not re.search(
        r"(?:^|\s)-all(?:\s|$)", spf.records[0], re.I
    ):
        spf_points = 10
    dmarc_points = 0
    if dmarc.status in ("absent", "invalid"):
        dmarc_points = 25
    elif dmarc.records:
        policy = re.search(
            r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)",
            dmarc.records[0],
            re.I,
        )
        dmarc_points = (
            25
            if not policy
            else {"none": 15, "quarantine": 5, "reject": 0}[
                policy.group(1).lower()
            ]
        )
    suspicious = sum(bool(link.flags) for link in report.links)
    auth_failed = any(
        h.name.lower() == "authentication-results"
        and re.search(
            r"\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|permerror)", h.value, re.I
        )
        for h in report.headers
    )
    network_points = (5 if not report.hops else 0) + (5 if auth_failed else 0)
    report.factors = [
        Factor(
            name="Header consistency",
            points=min(30, 10 * len(report.anomalies)),
            maximum=30,
            evidence=f"{len(report.anomalies)} anomalies × 10; capped at 30. Exact domain comparison, not proof of spoofing.",
        ),
        Factor(
            name="SPF posture",
            points=spf_points,
            maximum=20,
            evidence=f"{spf.status}: absent / duplicate / +all = 20; non-hardfail ending = 10; -all = 0. Unknown = 0 (unassessed).",
        ),
        Factor(
            name="DMARC posture",
            points=dmarc_points,
            maximum=25,
            evidence=f"{dmarc.status}: absent / duplicate / invalid p = 25; none = 15; quarantine = 5; reject = 0. Exact-domain policy only; unknown = 0.",
        ),
        Factor(
            name="URL heuristics",
            points=min(15, suspicious * 5),
            maximum=15,
            evidence=f"{suspicious} flagged URLs × 5; capped at 15. HTTP, IP literals, IDN and credentials are review signals.",
        ),
        Factor(
            name="Transport indicators",
            points=network_points,
            maximum=10,
            evidence=f"Missing Received = 5 ({not bool(report.hops)}); claimed authentication failure = 5 ({auth_failed}). Claimed results are untrusted.",
        ),
    ]
    report.score = sum(f.points for f in report.factors)
    report.classification = (
        "High risk"
        if report.score >= 75
        else "Elevated risk"
        if report.score >= 50
        else "Caution"
        if report.score >= 25
        else "Lower observed risk"
    )
    assessed = sum(f.status != "unknown" for f in (spf, dmarc))
    report.coverage = f"{assessed}/2 primary DNS policies assessed · unknown checks are not evidence of safety"
