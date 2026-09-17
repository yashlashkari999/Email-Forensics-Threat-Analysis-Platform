import reflex as rx
import asyncio
import logging
from app.states.evidence import Report
from app.states.parser import MAX_BYTES, parse_message
from app.states.dns_service import enrich
from app.states.report_service import build_pdf


class AnalysisState(rx.State):
    report: Report = Report()
    analyst: str = ""
    busy: bool = False
    ready: bool = False
    exporting: bool = False
    error: str = ""
    phase: str = ""
    _raw: bytes = b""
    _filename: str = ""

    @rx.event
    def set_analyst(self, value: str):
        self.analyst = value[:120]

    @rx.event
    async def handle_upload(self, files: list[rx.UploadFile]):
        if self.busy:
            return
        self.error = ""
        if len(files) != 1:
            self.error = "Select exactly one .eml evidence file."
            return
        try:
            self._raw = await files[0].read(MAX_BYTES + 1)
            self._filename = files[0].filename or ""
            self.busy = True
            self.phase = "01 / Validating evidence & preserving headers"
            yield AnalysisState.analyze
        except Exception as e:
            logging.exception(f"Error: {e}")
            self.error = "Upload could not be read. Please try again."
            self.busy = False

    @rx.event(background=True)
    async def analyze(self):
        async with self:
            raw, filename, analyst = self._raw, self._filename, self.analyst
        try:
            report = await asyncio.to_thread(
                parse_message, raw, filename, analyst
            )
            async with self:
                self.phase = (
                    "02 / Resolving live DNS · bounded checks, up to 12 seconds"
                )
                self._raw = b""
            report = await enrich(report)
            async with self:
                self.report = report
                self.ready = True
                self.phase = "03 / Evidence analysis complete"
        except Exception as e:
            logging.exception(f"Error: {e}")
            async with self:
                self.error = (
                    str(e).partition(":")[2]
                    if isinstance(e, ValueError) and ":" in str(e)
                    else "Unable to analyze this email. Verify that it is a raw .eml file."
                )
        finally:
            async with self:
                self.busy = False
                self._raw = b""

    @rx.event
    def new_analysis(self):
        if self.busy or self.exporting:
            return
        self.report = Report()
        self.ready = False
        self.error = ""
        self.phase = ""
        self._raw = b""
        self._filename = ""
        return rx.clear_selected_files("evidence")

    @rx.event
    async def export_pdf(self):
        if not self.ready or self.exporting:
            return
        self.exporting = True
        self.error = ""
        yield
        try:
            report = self.report.model_copy(deep=True)
            report.analyst = self.analyst.strip() or "Unassigned"
            pdf = await asyncio.to_thread(build_pdf, report)
            yield rx.download(data=pdf, filename=f"{report.case_id}.pdf")
        except Exception as e:
            logging.exception(f"Error: {e}")
            self.error = "PDF export failed. Your evidence remains available; please retry."
        finally:
            self.exporting = False
