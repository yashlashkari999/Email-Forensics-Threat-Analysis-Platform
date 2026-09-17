import reflex as rx
import asyncio
import logging
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from app.states.evidence import Report
from app.states.parser import MAX_BYTES, parse_message
from app.states.dns_service import enrich

api = FastAPI(
    title="Signal Email Forensics",
    version="1.0",
    description="Ephemeral raw-email triage. No message authentication or remote reputation verdicts.",
)


@api.post(
    "/api/v1/parse",
    response_model=Report,
    responses={
        400: {
            "description": "Unsupported filename or malformed multipart request"
        },
        413: {"description": "Maximum file size is 10 MiB"},
        422: {"description": "Missing upload or invalid email content"},
    },
)
async def parse_endpoint(
    file: UploadFile = File(...), analyst: str = Form("", max_length=120)
) -> Report:
    try:
        raw = await file.read(MAX_BYTES + 1)
        report = await asyncio.to_thread(
            parse_message, raw, file.filename or "", analyst
        )
        return await enrich(report)
    except ValueError as e:
        logging.exception(f"Error: {e}")
        code, _, detail = str(e).partition(":")
        raise HTTPException(
            status_code=int(code) if code in ("400", "413", "422") else 422,
            detail=detail or "Unable to interpret this email.",
        ) from e
    except Exception as e:
        logging.exception(f"Error: {e}")
        raise HTTPException(
            status_code=422,
            detail="Analysis could not complete. Check the raw email content and retry.",
        ) from e
    finally:
        await file.close()
