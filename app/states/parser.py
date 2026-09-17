import reflex as rx
import hashlib
import html
import ipaddress
import logging
import re
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import PurePath
from urllib.parse import urlsplit, urlunsplit
import mailparser
from app.states.evidence import Report, Header, Hop, Link

MAX_BYTES = 10 * 1024 * 1024


def domain_of(value: str) -> str:
    addresses = getaddresses([value])
    if len(addresses) != 1 or addresses[0][1].count("@") != 1:
        return ""
    domain = addresses[0][1].rsplit("@", 1)[1].rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as e:
        logging.exception(f"Error: {e}")
        return ""
    if (
        len(domain) > 253
        or "." not in domain
        or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in domain.split(".")
        )
    ):
        return ""
    return domain


def public_addresses(text: str) -> list[str]:
    found: list[str] = []
    # Broad tokens are validated by ipaddress, including compressed and mapped IPv6.
    for match in re.finditer(
        r"(?i)(?:IPv6:)?[0-9a-f:.]+(?:%[a-z0-9_-]+)?", text
    ):
        token = re.sub(r"^IPv6:", "", match.group(), flags=re.I).strip(".")
        if "%" in token:
            continue
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        if address.is_global and not (
            address.is_multicast
            or address.is_reserved
            or address.is_loopback
            or address.is_link_local
            or address.is_private
            or address.is_unspecified
        ):
            normalized = str(address)
            if normalized not in found:
                found.append(normalized)
    return found


def extract_links(text: str) -> list[Link]:
    links: list[Link] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"https?://[^\s<>\x00-\x20\"\']+", html.unescape(text), re.I
    ):
        raw = match.group().rstrip(".,;:!?")
        while raw.endswith(")") and raw.count(")") > raw.count("("):
            raw = raw[:-1]
        raw = raw.rstrip("]}")
        try:
            parts = urlsplit(raw)
            host = (parts.hostname or "").encode("idna").decode("ascii").lower()
            if not host or parts.scheme.lower() not in ("http", "https"):
                continue
            port = parts.port
            hostpart = f"[{host}]" if ":" in host else host
            authority = f"{hostpart}:{port}" if port is not None else hostpart
            if parts.username is not None:
                authority = f"{parts.netloc.rsplit('@', 1)[0]}@{authority}"
            clean = urlunsplit(
                (
                    parts.scheme.lower(),
                    authority,
                    parts.path,
                    parts.query,
                    parts.fragment,
                )
            )
            if clean in seen:
                continue
            seen.add(clean)
            flags: list[str] = []
            if parts.scheme.lower() == "http":
                flags.append("Unencrypted HTTP")
            if parts.username is not None:
                flags.append("Embedded credentials / deceptive authority")
            if "xn--" in host:
                flags.append("Internationalized hostname; review")
            try:
                ipaddress.ip_address(host)
                flags.append("IP-literal destination")
            except ValueError:
                pass
            links.append(Link(url=clean, host=host, flags=flags))
        except (ValueError, UnicodeError) as e:
            logging.exception(f"Error: {e}")
    return links


def parse_message(raw: bytes, filename: str, analyst: str = "") -> Report:
    if not filename.lower().endswith(".eml"):
        raise ValueError(
            "400:Upload a raw .eml file, not an archive or .msg file."
        )
    if len(raw) > MAX_BYTES:
        raise ValueError("413:File exceeds the 10 MiB evidence limit.")
    if not raw or b"\x00" in raw:
        raise ValueError(
            "422:Empty or binary content is not a valid raw email."
        )
    if not re.search(rb"\r?\n\r?\n", raw):
        raise ValueError("422:Missing email header/body separator.")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = [Header(name=k, value=v) for k, v in message.raw_items()]
    if not headers or not any(
        h.name.lower() in ("from", "received", "subject", "message-id", "date")
        for h in headers
    ):
        raise ValueError("422:No recognizable email headers found.")
    report = Report(
        case_id=f"EV-{uuid.uuid4().hex.upper()[:16]}",
        filename=PurePath(filename.replace("\\", "/")).name[:255],
        size=len(raw),
        timestamp=datetime.now(timezone.utc).isoformat(),
        analyst=analyst.strip()[:120] or "Unassigned",
        md5=hashlib.md5(raw, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(raw).hexdigest(),
        headers=headers,
    )
    names = [
        "From",
        "Return-Path",
        "Reply-To",
        "Subject",
        "Message-ID",
        "X-Originating-IP",
        "Authentication-Results",
        "DKIM-Signature",
    ]
    for name in names:
        values = [str(v) for v in message.get_all(name, [])]
        report.comparison.append(
            Header(name=name, value="\n".join(values) or "(absent)")
        )
        if (
            name in ("From", "Return-Path", "Reply-To", "Subject", "Message-ID")
            and len(values) > 1
        ):
            report.anomalies.append(
                f"Duplicate {name} headers ({len(values)}); interpretation is ambiguous."
            )
    report.subject = str(message.get("Subject", "(no subject)"))
    report.domain = domain_of(message.get("From", ""))
    if not report.domain:
        report.anomalies.append(
            "From does not contain one valid DNS sender domain."
        )
    for name in ("Return-Path", "Reply-To"):
        value = str(message.get(name, ""))
        domain = domain_of(value)
        if domain and report.domain and domain != report.domain:
            report.anomalies.append(
                f"{name} domain {domain} differs from From domain {report.domain}."
            )
    if not message.get("Message-ID"):
        report.anomalies.append("Message-ID is absent.")
    if message.defects:
        report.anomalies.append(
            "Email parser reported structural defects: "
            + ", ".join(type(d).__name__ for d in message.defects)
        )
    for header in headers:
        if header.name.lower() == "received":
            addresses = public_addresses(header.value)
            report.hops.append(
                Hop(
                    order=len(report.hops) + 1,
                    raw=header.value,
                    addresses=addresses,
                )
            )
            for address in addresses:
                if address not in report.public_ips:
                    report.public_ips.append(address)
    for value in message.get_all("X-Originating-IP", []):
        for address in public_addresses(value):
            if address not in report.public_ips:
                report.public_ips.append(address)
    bodies: list[str] = []
    for part in message.walk():
        if (
            part.get_content_type() in ("text/plain", "text/html")
            and part.get_content_disposition() != "attachment"
        ):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    bodies.append(
                        payload.decode(
                            part.get_content_charset() or "utf-8",
                            errors="replace",
                        )
                    )
                except LookupError as e:
                    logging.exception(f"Error: {e}")
                    bodies.append(payload.decode("utf-8", errors="replace"))
    try:
        parsed = mailparser.parse_from_bytes(raw)
        if not bodies:
            bodies.append(parsed.body or "")
    except Exception as e:
        logging.exception(f"Error: {e}")
        report.anomalies.append(
            "Supplementary mailparser decoding failed; standard email parser evidence retained."
        )
    report.links = extract_links("\n".join(bodies))
    return report
