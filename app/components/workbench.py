import reflex as rx
from app.states.analysis_state import AnalysisState as S
from app.states.evidence import Header, Hop, Link, Finding, Factor


BUTTON = "inline-flex items-center justify-center gap-2 rounded-sm bg-cyan-300 px-5 py-3 text-sm font-semibold text-[#0b1b28] transition hover:bg-cyan-200 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-cyan-300 disabled:opacity-40 disabled:cursor-not-allowed"
LABEL = "font-['Barlow_Condensed'] text-sm font-semibold uppercase tracking-[0.18em]"


def section_title(number: str, title: str, note: str) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(number, class_name="font-mono text-xs text-cyan-700"),
            rx.el.h2(
                title,
                class_name="font-['Barlow_Condensed'] text-2xl font-semibold uppercase tracking-wide text-[#132c3c]",
            ),
            class_name="flex items-center gap-3",
        ),
        rx.el.p(note, class_name="mt-1 text-xs leading-5 text-slate-500"),
        class_name="mb-6 border-b border-[#d9dcd5] pb-4",
    )


def brand_header() -> rx.Component:
    return rx.el.header(
        rx.el.a(
            rx.el.div(
                rx.icon("scan-line", class_name="h-7 w-7 text-cyan-300"),
                class_name="border border-cyan-300/30 p-2",
            ),
            rx.el.div(
                rx.el.div(
                    "SIGNAL",
                    class_name="font-['Barlow_Condensed'] text-3xl font-semibold leading-none tracking-[0.15em] text-[#f5f4ec]",
                ),
                rx.el.div(
                    "EMAIL FORENSICS LAB",
                    class_name="mt-1 font-mono text-[9px] tracking-[0.19em] text-slate-400",
                ),
            ),
            href="/",
            class_name="flex items-center gap-3",
        ),
        rx.el.div(
            rx.el.span(class_name="h-1.5 w-1.5 rounded-full bg-cyan-300"),
            "LOCAL EVIDENCE / LIVE DNS",
            class_name="hidden items-center gap-2 font-mono text-[10px] tracking-widest text-slate-400 md:flex",
        ),
        rx.el.a(
            "METHODOLOGY",
            rx.icon("arrow-up-right", class_name="h-3 w-3"),
            href="#methodology",
            class_name="flex items-center gap-2 text-[10px] font-semibold tracking-widest text-slate-300 hover:text-cyan-300",
        ),
        class_name="flex items-center justify-between border-b border-white/10 px-5 py-5 md:px-10",
    )


def analyst_field() -> rx.Component:
    return rx.el.div(
        rx.el.label(
            "ANALYST OF RECORD",
            html_for="analyst",
            class_name="font-['Barlow_Condensed'] text-sm font-semibold tracking-[0.15em] text-slate-500",
        ),
        rx.el.div(
            rx.icon("user-round", class_name="h-4 w-4 text-slate-500"),
            rx.el.input(
                id="analyst",
                placeholder="Enter analyst name (optional)",
                default_value=S.analyst,
                max_length=120,
                on_change=S.set_analyst.debounce(500),
                class_name="w-full bg-transparent py-3 text-sm text-slate-900 outline-hidden placeholder:text-slate-400",
            ),
            class_name="mt-2 flex items-center gap-3 border-b border-slate-300 focus-within:border-cyan-600",
        ),
    )


def signal_path() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.icon("mail", class_name="h-6 w-6"),
            rx.el.span(
                "RAW MESSAGE", class_name="font-mono text-[9px] tracking-wider"
            ),
            class_name="flex flex-col items-center gap-4 text-slate-300",
        ),
        rx.el.div(class_name="h-px min-w-4 flex-1 bg-cyan-300/40"),
        rx.el.div(
            rx.el.div(
                rx.icon("scan", class_name="h-9 w-9 text-cyan-300"),
                class_name="flex h-24 w-24 items-center justify-center rounded-full border border-cyan-300/60 outline-8 outline-cyan-300/5",
            ),
            rx.el.span(
                "EVIDENCE ENGINE",
                class_name="mt-4 font-mono text-[9px] tracking-wider text-cyan-300",
            ),
            class_name="flex flex-col items-center",
        ),
        rx.el.div(class_name="h-px min-w-4 flex-1 bg-cyan-300/40"),
        rx.el.div(
            rx.icon("file-check-2", class_name="h-6 w-6"),
            rx.el.span(
                "AUDITABLE REPORT",
                class_name="font-mono text-[9px] tracking-wider",
            ),
            class_name="flex flex-col items-center gap-4 text-slate-300",
        ),
        class_name="my-12 flex items-center gap-4 border-y border-white/10 py-12",
    )


def upload_panel() -> rx.Component:
    return rx.el.section(
        rx.el.div(
            rx.el.div(
                rx.el.span("01", class_name="font-mono text-xs text-cyan-700"),
                rx.el.span(
                    "EVIDENCE INTAKE",
                    class_name="font-['Barlow_Condensed'] text-lg font-semibold tracking-widest text-slate-700",
                ),
                class_name="flex items-center gap-3",
            ),
            rx.icon("fingerprint", class_name="h-6 w-6 text-slate-400"),
            class_name="mb-8 flex items-center justify-between",
        ),
        rx.el.h2(
            "Start with the source.",
            class_name="font-['Barlow_Condensed'] text-4xl font-medium text-[#132c3c]",
        ),
        rx.el.p(
            "Upload the original message. Every header matters.",
            class_name="mt-2 text-sm text-slate-500",
        ),
        rx.el.div(analyst_field(), class_name="my-8"),
        rx.upload.root(
            rx.el.div(
                rx.icon("upload", class_name="h-7 w-7 text-cyan-700"),
                class_name="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-cyan-900/5",
            ),
            rx.el.p(
                "Drop raw email evidence here",
                class_name="text-base font-semibold text-[#173344]",
            ),
            rx.el.p(
                "or click to browse files",
                class_name="mt-1 text-sm text-slate-500",
            ),
            rx.el.span(
                ".EML ONLY  /  MAX 10 MiB",
                class_name="mt-5 font-mono text-[10px] tracking-widest text-slate-400",
            ),
            id="evidence",
            accept={"message/rfc822": [".eml"]},
            max_files=1,
            multiple=False,
            max_size=10485760,
            disabled=S.busy,
            class_name="flex min-h-56 cursor-pointer flex-col items-center justify-center border border-dashed border-cyan-800/40 bg-[#eaece6] p-6 text-center transition hover:border-cyan-700 hover:bg-[#e2e8e2] focus-within:outline-2 focus-within:outline-cyan-700",
        ),
        rx.el.div(
            rx.foreach(
                rx.selected_files("evidence"),
                lambda name: rx.el.div(
                    rx.icon("paperclip", class_name="h-3 w-3 shrink-0"),
                    rx.el.span(name, class_name="truncate"),
                    class_name="mt-3 flex items-center gap-2 font-mono text-xs text-cyan-800",
                ),
            ),
            class_name="min-h-8",
        ),
        rx.el.button(
            rx.cond(
                S.busy,
                rx.icon("loader-circle", class_name="h-4 w-4 animate-spin"),
                rx.icon("scan-line", class_name="h-4 w-4"),
            ),
            rx.cond(S.busy, "Analysis in progress", "Analyze evidence"),
            rx.icon("arrow-right", class_name="ml-auto h-4 w-4"),
            on_click=S.handle_upload(rx.upload_files(upload_id="evidence")),
            disabled=S.busy | (rx.selected_files("evidence").length() == 0),
            class_name="mt-3 flex w-full items-center justify-center gap-3 bg-[#123344] px-5 py-4 text-sm font-semibold text-[#f6f5ed] transition hover:bg-[#1e485b] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-cyan-700 disabled:cursor-not-allowed disabled:opacity-50",
        ),
        rx.cond(
            S.busy,
            rx.el.div(
                rx.el.p(
                    S.phase,
                    role="status",
                    class_name="mt-4 animate-pulse font-mono text-xs leading-5 text-cyan-800",
                ),
                rx.el.progress(class_name="mt-3 h-1 w-full accent-cyan-700"),
                class_name="w-full",
            ),
        ),
        rx.el.p(
            rx.icon("lock-keyhole", class_name="h-3 w-3 shrink-0"),
            "Session-only evidence. No database. DNS names are queried; message bodies are not sent to intelligence providers.",
            class_name="mt-6 flex items-start gap-2 text-[11px] leading-5 text-slate-500",
        ),
        class_name="bg-[#f4f3eb] p-6 md:p-9",
    )


def uplink() -> rx.Component:
    return rx.el.div(
        rx.el.section(
            rx.el.div(
                rx.el.span(class_name="h-1.5 w-1.5 bg-cyan-300"),
                "FORENSIC WORKSPACE / READY FOR INTAKE",
                class_name="mb-8 flex items-center gap-3 font-mono text-[10px] tracking-[0.14em] text-cyan-300",
            ),
            rx.el.h1(
                "Trace the message.",
                rx.el.br(),
                rx.el.span("Expose the signals.", class_name="text-[#88a1ad]"),
                class_name="font-['Barlow_Condensed'] text-5xl font-medium leading-[1.03] tracking-tight text-[#f4f3eb] sm:text-6xl lg:text-7xl",
            ),
            rx.el.p(
                "From raw headers to defensible evidence. Inspect the transmission trail, interrogate sender DNS, and turn uncertainty into a transparent investigation.",
                class_name="mt-7 max-w-lg text-sm leading-7 text-slate-400",
            ),
            signal_path(),
            rx.el.div(
                rx.el.div(
                    rx.el.p(
                        "PRESERVE",
                        class_name="font-mono text-[10px] tracking-widest text-cyan-300",
                    ),
                    rx.el.p(
                        "Original header order. Exact-byte hashes.",
                        class_name="mt-2 text-xs leading-5 text-slate-400",
                    ),
                ),
                rx.el.div(
                    rx.el.p(
                        "EXPLAIN",
                        class_name="font-mono text-[10px] tracking-widest text-cyan-300",
                    ),
                    rx.el.p(
                        "Every risk factor. Every limitation.",
                        class_name="mt-2 text-xs leading-5 text-slate-400",
                    ),
                ),
                class_name="grid grid-cols-2 gap-6",
            ),
            class_name="py-5 lg:pr-12",
        ),
        upload_panel(),
        class_name="grid items-start gap-10 py-10 lg:grid-cols-[1.15fr_1fr] lg:gap-16 lg:py-14",
    )


def factor_row(factor: Factor) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(factor.name, class_name="text-sm text-slate-300"),
            rx.el.span(
                f"{factor.points} / {factor.maximum}",
                class_name="font-mono text-xs text-amber-300",
            ),
            class_name="flex justify-between gap-3",
        ),
        rx.el.progress(
            value=factor.points,
            max=factor.maximum,
            class_name="my-2 h-1 w-full accent-amber-300",
        ),
        rx.el.details(
            rx.el.summary(
                "Factor evidence",
                class_name="cursor-pointer font-mono text-[10px] text-slate-500 hover:text-cyan-300",
            ),
            rx.el.p(
                factor.evidence,
                class_name="mt-2 text-xs leading-5 text-slate-400",
            ),
        ),
        class_name="border-b border-white/10 py-4",
    )


def threat_dial() -> rx.Component:
    return rx.el.section(
        rx.el.div(
            "DNS-FOCUSED THREAT INDEX",
            class_name="font-['Barlow_Condensed'] text-lg font-semibold tracking-[0.15em] text-slate-300",
        ),
        rx.el.div(
            rx.el.div(
                rx.el.div(
                    rx.el.span(
                        S.report.score,
                        class_name="font-['Barlow_Condensed'] text-8xl font-medium leading-none text-[#f4f3eb]",
                    ),
                    rx.el.span(
                        "/ 100",
                        class_name="mt-2 font-mono text-xs text-slate-500",
                    ),
                    rx.el.span(
                        S.report.classification,
                        class_name=rx.cond(
                            S.report.score >= 50,
                            "mt-4 text-xs font-semibold uppercase tracking-wider text-[#ff755a]",
                            "mt-4 text-xs font-semibold uppercase tracking-wider text-amber-300",
                        ),
                    ),
                    class_name="flex h-48 w-48 flex-col items-center justify-center rounded-full border border-white/10",
                ),
                class_name=rx.cond(
                    S.report.score >= 50,
                    "flex h-60 w-60 items-center justify-center rounded-full border-[8px] border-[#f16449] outline-1 outline-offset-8 outline-white/10",
                    "flex h-60 w-60 items-center justify-center rounded-full border-[8px] border-amber-300 outline-1 outline-offset-8 outline-white/10",
                ),
            ),
            class_name="flex justify-center py-10",
        ),
        rx.el.p(
            "Triage signal. Not a verdict.",
            class_name="text-center text-xs text-slate-500",
        ),
        rx.el.div(rx.foreach(S.report.factors, factor_row), class_name="mt-6"),
        rx.el.p(
            S.report.coverage,
            class_name="mt-5 font-mono text-[10px] leading-5 text-slate-400",
        ),
        class_name="border border-white/10 bg-[#102432] p-6",
    )


def header_row(header: Header) -> rx.Component:
    return rx.el.div(
        rx.el.dt(
            header.name,
            class_name="font-['Barlow_Condensed'] text-sm font-semibold uppercase tracking-wider text-slate-500",
        ),
        rx.el.dd(
            header.value,
            class_name="whitespace-pre-wrap break-all font-mono text-xs leading-6 text-[#1d3848]",
        ),
        class_name="grid gap-1 border-b border-[#d9dcd5] py-3 sm:grid-cols-[130px_1fr] sm:gap-4",
    )


def hop_row(hop: Hop) -> rx.Component:
    return rx.el.li(
        rx.el.div(
            rx.el.span(
                f"{hop.order}",
                class_name="flex h-8 w-8 items-center justify-center rounded-full border border-cyan-700/40 bg-[#f4f3eb] font-mono text-xs text-cyan-800",
            ),
            class_name="absolute -left-4 top-0",
        ),
        rx.el.div(
            rx.cond(
                hop.addresses.length() > 0,
                rx.el.div(
                    rx.foreach(
                        hop.addresses,
                        lambda ip: rx.el.span(
                            ip,
                            class_name="w-fit border border-cyan-700/20 bg-cyan-700/5 px-2 py-1 font-mono text-xs text-cyan-800",
                        ),
                    ),
                    class_name="flex flex-wrap gap-2",
                ),
                rx.el.p(
                    "No global address in this header",
                    class_name="py-1 font-mono text-xs text-slate-500",
                ),
            ),
            rx.el.p(
                hop.raw,
                class_name="mt-3 whitespace-pre-wrap break-all font-mono text-[11px] leading-6 text-slate-600",
            ),
            class_name="pb-7 pl-8",
        ),
        class_name="relative border-l border-cyan-700/30",
    )


def transmissions() -> rx.Component:
    return rx.el.section(
        section_title(
            "03",
            "Transmission path",
            "Received headers in original wire order · newest first. Routing claims are not independently verified.",
        ),
        rx.el.div(
            rx.el.div(
                rx.icon("network", class_name="h-5 w-5 text-cyan-700"),
                rx.el.span(
                    f"{S.report.hops.length()} RECEIVED HEADERS",
                    class_name="font-mono text-[10px] tracking-wider text-slate-600",
                ),
                class_name="flex items-center gap-3",
            ),
            rx.el.span(
                f"{S.report.public_ips.length()} GLOBAL IPs",
                class_name="font-mono text-[10px] text-cyan-700",
            ),
            class_name="mb-8 flex flex-wrap items-center justify-between gap-3 border border-[#d9dcd5] px-4 py-4",
        ),
        rx.cond(
            S.report.hops.length() > 0,
            rx.el.ol(rx.foreach(S.report.hops, hop_row), class_name="ml-4"),
            rx.el.p(
                "No Received headers were found. A transmission path cannot be reconstructed.",
                class_name="py-5 text-sm text-slate-500",
            ),
        ),
        rx.el.details(
            rx.el.summary(
                "Unique global IP inventory (including X-Originating-IP)",
                class_name="cursor-pointer text-xs text-cyan-800",
            ),
            rx.el.p(
                S.report.public_ips.join(" · "),
                class_name="mt-3 break-all font-mono text-xs text-slate-600",
            ),
        ),
        rx.el.p(
            "Non-global IP candidates are excluded from the inventory. Original header text remains intact as evidence.",
            class_name="mt-5 text-[11px] leading-5 text-slate-500",
        ),
        id="transmission",
        class_name="bg-[#f4f3eb] p-6 md:p-8",
    )


def link_row(link: Link) -> rx.Component:
    return rx.el.tr(
        rx.el.td(
            rx.el.p(
                link.url,
                class_name="break-all font-mono text-xs leading-5 text-[#233f50]",
            ),
            rx.el.p(link.host, class_name="mt-2 text-[10px] text-slate-500"),
            class_name="max-w-xl px-4 py-4 align-top",
        ),
        rx.el.td(
            rx.cond(
                link.flags.length() > 0,
                rx.el.div(
                    rx.foreach(
                        link.flags,
                        lambda flag: rx.el.span(
                            flag,
                            class_name="mb-1 block w-fit bg-amber-100 px-2 py-1 text-[10px] text-amber-800",
                        ),
                    )
                ),
                rx.el.span(
                    "No lexical flags", class_name="text-xs text-slate-500"
                ),
            ),
            class_name="w-52 px-4 py-4 align-top",
        ),
        class_name="border-b border-[#d9dcd5] odd:bg-white/30 hover:bg-white/60",
    )


def finding_row(finding: Finding) -> rx.Component:
    return rx.el.details(
        rx.el.summary(
            rx.el.span(
                finding.name, class_name="text-sm font-semibold text-[#173344]"
            ),
            rx.el.span(
                finding.status,
                class_name=rx.cond(
                    (finding.status == "published")
                    | (finding.status == "observed")
                    | (finding.status == "completed"),
                    "ml-auto w-fit bg-cyan-900/5 px-2 py-1 font-mono text-[10px] uppercase text-cyan-800",
                    "ml-auto w-fit bg-amber-100 px-2 py-1 font-mono text-[10px] uppercase text-amber-800",
                ),
            ),
            rx.icon("chevron-down", class_name="h-3 w-3 text-slate-400"),
            class_name="flex cursor-pointer list-none items-center gap-3 py-4 focus-visible:outline-2 focus-visible:outline-cyan-700",
        ),
        rx.el.p(
            finding.query,
            class_name="mb-2 break-all font-mono text-xs text-cyan-800",
        ),
        rx.el.pre(
            finding.detail,
            class_name="whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-slate-600",
        ),
        rx.foreach(
            finding.records,
            lambda record: rx.el.pre(
                record,
                class_name="my-3 whitespace-pre-wrap break-all border-l-2 border-cyan-700/40 bg-white/40 p-3 font-mono text-[11px] leading-5 text-slate-600",
            ),
        ),
        class_name="border-b border-[#d9dcd5]",
    )


def unavailable_panel() -> rx.Component:
    return rx.el.section(
        rx.el.div(
            rx.icon("radar", class_name="h-5 w-5 text-slate-500"),
            rx.el.h3(
                "INTELLIGENCE BOUNDARY",
                class_name="font-['Barlow_Condensed'] text-lg tracking-wider text-slate-300",
            ),
            class_name="flex items-center gap-3",
        ),
        rx.el.p(
            "No invented certainty.", class_name="mt-4 text-sm text-slate-300"
        ),
        rx.el.p(
            "Geographic mapping and remote language intelligence are unavailable. Reputation feeds have not been queried.",
            class_name="mt-2 text-xs leading-6 text-slate-500",
        ),
        rx.el.div(
            rx.foreach(
                S.report.unavailable,
                lambda item: rx.el.div(
                    rx.icon("minus", class_name="h-3 w-3 text-slate-600"),
                    item,
                    class_name="flex items-center gap-2 border-t border-white/10 py-3 font-mono text-[10px] text-slate-400",
                ),
            ),
            class_name="mt-5",
        ),
        rx.el.p(
            "EXCLUDED FROM SCORING",
            class_name="mt-3 font-mono text-[9px] tracking-widest text-slate-500",
        ),
        class_name="border border-white/10 p-6",
    )


def custody_panel() -> rx.Component:
    return rx.el.section(
        section_title(
            "06",
            "Chain of custody",
            "Fingerprints of the exact bytes received. Save the export before clearing the session.",
        ),
        rx.el.div(
            rx.el.span(
                "SHA-256 / INTEGRITY REFERENCE",
                class_name="font-mono text-[10px] text-cyan-700",
            ),
            rx.el.p(
                S.report.sha256,
                class_name="mt-2 break-all font-mono text-xs leading-6 text-slate-700",
            ),
            rx.el.span(
                "MD5 / COMPATIBILITY",
                class_name="mt-4 block font-mono text-[10px] text-slate-500",
            ),
            rx.el.p(
                S.report.md5,
                class_name="mt-2 break-all font-mono text-xs text-slate-600",
            ),
        ),
        rx.el.div(analyst_field(), class_name="mt-7"),
        rx.el.button(
            rx.cond(
                S.exporting,
                rx.icon("loader-circle", class_name="h-4 w-4 animate-spin"),
                rx.icon("file-down", class_name="h-4 w-4"),
            ),
            rx.cond(S.exporting, "Building report…", "Export evidence PDF"),
            on_click=S.export_pdf,
            disabled=S.exporting,
            class_name="mt-6 flex w-full items-center justify-center gap-2 bg-[#123344] px-5 py-4 text-sm font-semibold text-white hover:bg-[#1e485b] focus-visible:outline-2 focus-visible:outline-cyan-700 disabled:opacity-50",
        ),
        class_name="bg-[#f4f3eb] p-6",
    )


def results() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(
                rx.el.p(
                    "ANALYSIS COMPLETE / SESSION EVIDENCE",
                    class_name="font-mono text-[10px] tracking-[0.15em] text-cyan-300",
                ),
                rx.el.h1(
                    "Evidence workbench",
                    class_name="mt-3 font-['Barlow_Condensed'] text-5xl font-medium text-[#f4f3eb]",
                ),
                rx.el.p(
                    S.report.case_id,
                    class_name="mt-3 font-mono text-xs text-slate-400",
                ),
            ),
            rx.el.button(
                rx.icon("plus", class_name="h-4 w-4"),
                "New analysis",
                on_click=S.new_analysis,
                disabled=S.exporting,
                class_name="flex items-center gap-2 border border-white/20 px-4 py-3 text-xs text-slate-300 transition hover:border-cyan-300 hover:text-cyan-300 disabled:opacity-40",
            ),
            class_name="flex flex-wrap items-center justify-between gap-5 py-9",
        ),
        rx.el.div(
            rx.icon(
                "triangle-alert", class_name="h-5 w-5 shrink-0 text-amber-300"
            ),
            rx.el.div(
                rx.el.p(
                    f"{S.report.classification} · {S.report.score}/100",
                    class_name="text-sm font-semibold text-amber-200",
                ),
                rx.el.p(
                    "Assess the evidence, not just the score. Unavailable checks contribute no points; a low score is not a safety guarantee.",
                    class_name="mt-1 text-xs leading-5 text-slate-400",
                ),
            ),
            class_name="mb-7 flex items-start gap-4 border-l-2 border-amber-300 bg-amber-300/5 px-5 py-4",
        ),
        rx.el.div(
            rx.el.div(
                threat_dial(),
                custody_panel(),
                unavailable_panel(),
                class_name="flex min-w-0 flex-col gap-6",
            ),
            rx.el.div(
                rx.el.section(
                    section_title(
                        "01",
                        "Evidence manifest",
                        "Original file metadata · immutable intake fingerprints",
                    ),
                    rx.el.p(
                        S.report.filename,
                        class_name="break-all text-lg font-semibold text-[#173344]",
                    ),
                    rx.el.p(
                        f"{S.report.size:,} bytes / {S.report.timestamp}",
                        class_name="mt-3 break-all font-mono text-[11px] leading-6 text-slate-500",
                    ),
                    rx.el.p(
                        S.report.subject,
                        class_name="mt-5 border-l-2 border-cyan-700/40 pl-4 text-sm text-slate-700",
                    ),
                    class_name="bg-[#f4f3eb] p-6 md:p-8",
                ),
                rx.el.section(
                    section_title(
                        "02",
                        "Identity & header comparison",
                        "Exact domains are compared. Legitimate forwarding may cause mismatches.",
                    ),
                    rx.cond(
                        S.report.anomalies.length() > 0,
                        rx.el.div(
                            rx.foreach(
                                S.report.anomalies,
                                lambda anomaly: rx.el.p(
                                    rx.icon(
                                        "flag",
                                        class_name="mt-0.5 h-3 w-3 shrink-0",
                                    ),
                                    anomaly,
                                    class_name="flex items-start gap-2 text-xs leading-5 text-amber-900",
                                ),
                            ),
                            class_name="mb-5 flex flex-col gap-3 border border-amber-300/40 bg-amber-100/60 p-4",
                        ),
                        rx.el.p(
                            "No configured header anomalies detected.",
                            class_name="mb-4 text-xs text-cyan-800",
                        ),
                    ),
                    rx.el.dl(rx.foreach(S.report.comparison, header_row)),
                    rx.el.details(
                        rx.el.summary(
                            "Inspect all original headers",
                            class_name="mt-5 cursor-pointer text-xs font-semibold text-cyan-800",
                        ),
                        rx.el.dl(rx.foreach(S.report.headers, header_row)),
                    ),
                    class_name="bg-[#f4f3eb] p-6 md:p-8",
                ),
                transmissions(),
                rx.el.section(
                    section_title(
                        "04",
                        "URL artifacts",
                        "Extracted from inline text and HTML. Destinations are deliberately not clickable or fetched.",
                    ),
                    rx.cond(
                        S.report.links.length() > 0,
                        rx.el.div(
                            rx.el.table(
                                rx.el.thead(
                                    rx.el.tr(
                                        rx.el.th(
                                            rx.el.span(
                                                rx.icon(
                                                    "link", class_name="h-3 w-3"
                                                ),
                                                "DESTINATION",
                                                class_name="flex items-center gap-2",
                                            ),
                                            class_name="px-4 py-3 text-left font-mono text-[10px] text-slate-500",
                                        ),
                                        rx.el.th(
                                            rx.el.span(
                                                rx.icon(
                                                    "flag", class_name="h-3 w-3"
                                                ),
                                                "INDICATORS",
                                                class_name="flex items-center gap-2",
                                            ),
                                            class_name="px-4 py-3 text-left font-mono text-[10px] text-slate-500",
                                        ),
                                    )
                                ),
                                rx.el.tbody(
                                    rx.foreach(S.report.links, link_row)
                                ),
                                class_name="table-auto w-full",
                            ),
                            class_name="overflow-hidden border border-[#d9dcd5]",
                        ),
                        rx.el.p(
                            "No HTTP/HTTPS links found in the decoded message bodies.",
                            class_name="py-5 text-sm text-slate-500",
                        ),
                    ),
                    class_name="bg-[#f4f3eb] p-6 md:p-8",
                ),
                rx.el.section(
                    section_title(
                        "05",
                        "DNS & authentication evidence",
                        "Live configuration, not a message-level verdict. Expand a check to inspect the source records.",
                    ),
                    rx.el.div(rx.foreach(S.report.dns, finding_row)),
                    class_name="bg-[#f4f3eb] p-6 md:p-8",
                ),
                class_name="flex min-w-0 flex-col gap-6",
            ),
            class_name="grid items-start gap-6 lg:grid-cols-[320px_minmax(0,1fr)] xl:grid-cols-[360px_minmax(0,1fr)]",
        ),
    )


def methodology() -> rx.Component:
    return rx.el.section(
        rx.el.div(
            rx.el.span(
                "PROTOCOL / 01",
                class_name="font-mono text-[10px] tracking-widest text-cyan-300",
            ),
            rx.el.h2(
                "Evidence first. Assumptions disclosed.",
                class_name="mt-3 font-['Barlow_Condensed'] text-3xl text-[#f4f3eb]",
            ),
            class_name="lg:w-1/3",
        ),
        rx.el.div(
            rx.el.p(
                S.report.methodology,
                class_name="text-xs leading-6 text-slate-400",
            ),
            rx.el.details(
                rx.el.summary(
                    "Scope, limitations & unavailable checks",
                    class_name="mt-5 cursor-pointer text-xs text-cyan-300",
                ),
                rx.el.div(
                    rx.foreach(
                        S.report.limitations,
                        lambda item: rx.el.p(
                            item,
                            class_name="mt-3 text-xs leading-6 text-slate-400",
                        ),
                    )
                ),
            ),
            class_name="min-w-0 flex-1",
        ),
        id="methodology",
        class_name="mt-14 flex flex-col gap-7 border-t border-white/10 py-10 lg:flex-row lg:gap-16",
    )


def workbench() -> rx.Component:
    return rx.el.div(
        brand_header(),
        rx.el.main(
            rx.cond(
                S.error != "",
                rx.el.div(
                    rx.icon("circle-alert", class_name="h-5 w-5 shrink-0"),
                    rx.el.div(
                        rx.el.p(
                            "Evidence could not be processed",
                            class_name="text-sm font-semibold",
                        ),
                        rx.el.p(S.error, class_name="mt-1 text-xs"),
                    ),
                    role="alert",
                    class_name="mt-6 flex items-start gap-3 border border-red-400/30 bg-red-400/10 p-4 text-red-200",
                ),
            ),
            rx.cond(S.ready, results(), uplink()),
            methodology(),
            class_name="mx-auto w-full max-w-[1480px] px-5 md:px-10",
        ),
        rx.el.footer(
            rx.el.span(
                "SIGNAL / FORENSIC EVIDENCE LAB",
                class_name="font-mono text-[9px] tracking-widest text-slate-500",
            ),
            rx.el.span(
                "EPHEMERAL BY DESIGN · NO DATABASE",
                class_name="font-mono text-[9px] tracking-widest text-slate-500",
            ),
            class_name="flex flex-wrap justify-between gap-4 border-t border-white/10 px-5 py-5 md:px-10",
        ),
        class_name="min-h-dvh bg-[#0b1b28] font-['Inter'] text-slate-300 selection:bg-cyan-300/30",
    )
