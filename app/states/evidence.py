import reflex as rx
from pydantic import BaseModel, Field


class Header(BaseModel):
    name: str = ""
    value: str = ""


class Hop(BaseModel):
    order: int = 0
    raw: str = ""
    addresses: list[str] = Field(default_factory=list)


class Link(BaseModel):
    url: str = ""
    host: str = ""
    flags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    name: str = ""
    status: str = ""
    query: str = ""
    records: list[str] = Field(default_factory=list)
    detail: str = ""


class Factor(BaseModel):
    name: str = ""
    points: int = 0
    maximum: int = 0
    evidence: str = ""


class Report(BaseModel):
    case_id: str = ""
    filename: str = ""
    size: int = 0
    timestamp: str = ""
    analyst: str = "Unassigned"
    md5: str = ""
    sha256: str = ""
    subject: str = ""
    domain: str = ""
    headers: list[Header] = Field(default_factory=list)
    comparison: list[Header] = Field(default_factory=list)
    hops: list[Hop] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)
    links: list[Link] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    dns: list[Finding] = Field(default_factory=list)
    factors: list[Factor] = Field(default_factory=list)
    score: int = 0
    classification: str = "Awaiting evidence"
    coverage: str = ""
    methodology: str = "Fixed 100-point rubric: header anomalies 30, SPF posture 20, DMARC posture 25, URL heuristics 15, network/header indicators 10. Points are additive and capped within each factor; no feed-based normalization. Unknown DNS checks contribute zero, not a clean bill of health. 0–24 lower observed risk; 25–49 caution; 50–74 elevated; 75–100 high. This is a triage index, not a probability or a message authentication verdict."
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Headers and Authentication-Results are untrusted sender-supplied evidence unless independently corroborated. Received wire order is newest first, not independently verified routing.",
            "Live DNS reflects analysis time, not send time. SPF/DMARC configuration checks do not authenticate this message. DKIM cryptographic signature verification is out of scope; missing common selectors is inconclusive.",
            "No URLs are visited and no attachments are executed. Link flags are lexical heuristics, not reputation verdicts. Exact domain mismatches may be legitimate forwarding or third-party sending.",
            "GeoIP, VirusTotal, IPQualityScore, and remote NLP are not configured and excluded from scoring. No coordinates or threat-feed results are inferred.",
            "Evidence is held ephemerally for this session; no database or original-file archive. Export the report before resetting. MD5 is a compatibility fingerprint; SHA-256 is the integrity reference.",
        ]
    )
    unavailable: list[str] = Field(
        default_factory=lambda: [
            "GeoIP · not configured",
            "VirusTotal · not configured",
            "IPQualityScore · not configured",
            "Remote NLP · not configured",
        ]
    )
