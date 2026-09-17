import reflex as rx
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from app.states.evidence import Report


def build_pdf(report: Report) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        title=f"SIGNAL Evidence Report {report.case_id}",
        author=report.analyst,
        rightMargin=42,
        leftMargin=42,
        topMargin=44,
        bottomMargin=44,
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Evidence",
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#182c3c"),
            spaceAfter=7,
            splitLongWords=True,
            alignment=TA_LEFT,
        )
    )
    story = []

    def paragraph(text: str, style: str = "Evidence") -> None:
        safe = escape(text).replace("\n", "<br/>")
        story.append(Paragraph(safe, styles[style]))

    def section(title: str) -> None:
        story.append(Spacer(1, 12))
        paragraph(title, "Heading2")

    paragraph("SIGNAL / EMAIL FORENSICS", "Title")
    paragraph("CHAIN-OF-CUSTODY • ANALYSIS EXPORT", "Heading2")
    section("01 / Evidence intake")
    for label, value in [
        ("Case ID", report.case_id),
        ("Analyst", report.analyst),
        ("Analysis timestamp (UTC)", report.timestamp),
        ("Filename", report.filename),
        ("Bytes", str(report.size)),
        ("MD5 (compatibility only)", report.md5),
        ("SHA-256 (integrity reference)", report.sha256),
    ]:
        paragraph(f"{label}: {value}")
    paragraph(
        "Hashes cover the exact uploaded bytes. This report records intake and analysis, not custody before upload. Original evidence is not embedded or archived."
    )
    section("02 / Evidence summary & transparent threat index")
    paragraph(
        f"{report.score}/100 — {report.classification}\nSubject: {report.subject}\nSender domain: {report.domain or 'unresolved'}\n{report.coverage}"
    )
    for anomaly in report.anomalies:
        paragraph(f"Anomaly: {anomaly}")
    if not report.anomalies:
        paragraph("No header anomalies identified by the configured rules.")
    for factor in report.factors:
        paragraph(
            f"{factor.name}: {factor.points}/{factor.maximum}. {factor.evidence}"
        )
    paragraph(report.methodology)
    section("03 / Isolated header comparison")
    for header in report.comparison:
        paragraph(f"{header.name}: {header.value}")
    section("04 / Transmission evidence — original wire order, newest first")
    for hop in report.hops:
        paragraph(
            f"Hop {hop.order} — global IP candidates: {', '.join(hop.addresses) or 'none'}\n{hop.raw}"
        )
    if not report.hops:
        paragraph("No Received headers present.")
    paragraph(
        f"Unique global addresses, first-seen order: {', '.join(report.public_ips) or 'none'}"
    )
    section("05 / URL artifacts — not visited")
    for link in report.links:
        paragraph(
            f"{link.url}\nHost: {link.host}\nIndicators: {', '.join(link.flags) or 'No configured lexical flags'}"
        )
    if not report.links:
        paragraph(
            "No HTTP/HTTPS URLs extracted from inline text or HTML bodies."
        )
    section("06 / Live DNS & authentication posture")
    for finding in report.dns:
        paragraph(
            f"{finding.name} / {finding.status}\nQuery: {finding.query}\n{finding.detail}\n"
            + "\n".join(finding.records)
        )
    section("07 / Complete headers — preserved sequence and repeated fields")
    for header in report.headers:
        paragraph(f"{header.name}: {header.value}")
    section("08 / Scope & limitations")
    for limitation in report.limitations:
        paragraph(limitation)
    for service in report.unavailable:
        paragraph(service)

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#536474"))
        canvas.drawString(
            42, 25, f"{report.case_id} / Ephemeral evidence export"
        )
        canvas.drawRightString(553, 25, f"Page {doc.page}")

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
