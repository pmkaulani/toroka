"""Guest-accessible, local-first email forensics. Raw content is never persisted."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from starlette.concurrency import run_in_threadpool

from .deps import Ctx, ctx, throttle
from toroka_email_forensics import analyze_email
from toroka_email_forensics.analyzer import MAX_EMAIL_BYTES

router = APIRouter(tags=["email-forensics"])
ALLOWED_EXTENSIONS = {".eml", ".txt", ".headers"}
ALLOWED_CONTENT_TYPES = {"message/rfc822", "text/plain", "application/octet-stream"}


@router.post("/v1/email/analyze")
async def analyze_email_route(
    request: Request,
    file: UploadFile | None = File(default=None),
    raw_email: str | None = Form(default=None),
    allow_dns_checks: bool = Form(default=False),
    c: Ctx = Depends(ctx),
):
    """Analyze an original .eml or pasted raw email. No account or paid API key required."""
    throttle(request, c, "email_forensics", (10, 3600))
    if bool(file) == bool(raw_email and raw_email.strip()):
        raise HTTPException(422, "Upload one .eml file or paste the complete raw email, not both.")

    if file is not None:
        filename = (file.filename or "").lower()
        content_type = (file.content_type or "application/octet-stream").lower().split(";", 1)[0].strip()
        suffix = filename[filename.rfind("."):] if "." in filename else ""
        if (suffix and suffix not in ALLOWED_EXTENSIONS) or (not suffix and content_type not in ALLOWED_CONTENT_TYPES):
            await file.close()
            raise HTTPException(415, "Upload an original .eml or plain-text email/header file. Outlook .msg files are not supported.")
        raw = await file.read(MAX_EMAIL_BYTES + 1)
        await file.close()
    else:
        raw = (raw_email or "").encode("utf-8", errors="replace")

    if not raw:
        raise HTTPException(422, "The email content is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise HTTPException(413, "The email exceeds Toroka's 5 MB inspection limit.")
    if b"\x00" in raw[:4096]:
        raise HTTPException(415, "This appears to be a binary mail format. Export or save it as .eml first.")

    try:
        result = await run_in_threadpool(
            analyze_email,
            raw,
            trusted_authserv_ids=c.settings.email_trusted_authserv_ids,
            allow_dns_checks=allow_dns_checks,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception:
        # Do not log message content or parser exceptions that could include it.
        raise HTTPException(422, "Toroka could not safely analyze this email. Try exporting the original message as .eml.")
    return result
