import hmac
import os
import re
from html import unescape
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="ReplyTrim – Email Reply Cleaner API",
    version="1.0.0",
)


RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "")


class CleanEmailRequest(BaseModel):
    content: str = Field(min_length=1, max_length=100_000)
    content_type: Literal["text", "html"] = "text"
    output_format: Literal["text", "markdown"] = "text"
    remove_signature: bool = True
    remove_quoted_history: bool = True
    remove_disclaimer: bool = True
    remove_mobile_footer: bool = True


class EmailParts(BaseModel):
    reply: str
    signature: str | None = None
    quoted_history: str | None = None
    disclaimer: str | None = None
    mobile_footer: str | None = None


class CleanEmailResponse(BaseModel):
    clean_reply: str
    parts: EmailParts
    removed_sections: list[str]
    input_characters: int
    output_characters: int


def verify_proxy_secret(received_secret: str | None) -> None:
    if not RAPIDAPI_PROXY_SECRET:
        return

    if not received_secret or not hmac.compare_digest(
        received_secret,
        RAPIDAPI_PROXY_SECRET,
    ):
        raise HTTPException(
            status_code=403,
            detail="Direct access is disabled; call this API through RapidAPI",
        )


def html_to_text(content: str) -> str:
    text = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        content,
    )
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return unescape(text)


def normalize_text(content: str) -> str:
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    content = re.sub(r"[ \t]+\n", "\n", content)
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip()


def extract_mobile_footer(text: str) -> tuple[str, str | None]:
    patterns = [
        r"(?im)^\s*Sent from my iPhone\s*$",
        r"(?im)^\s*Sent from my iPad\s*$",
        r"(?im)^\s*Sent from my Android(?: device)?\s*$",
        r"(?im)^\s*Sent from Samsung Mobile\s*$",
        r"(?im)^\s*Get Outlook for (?:iOS|Android)\s*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            footer = match.group(0).strip()
            cleaned = f"{text[:match.start()]}\n{text[match.end():]}"
            return normalize_text(cleaned), footer

    return text, None


def extract_quoted_history(text: str) -> tuple[str, str | None]:
    patterns = [
        r"(?im)^\s*On .+ wrote:\s*$",
        r"(?im)^\s*From:\s.+$",
        r"(?im)^\s*-{2,}\s*Original Message\s*-{2,}\s*$",
        r"(?im)^\s*-{2,}\s*Forwarded message\s*-{2,}\s*$",
        r"(?im)^\s*_{5,}\s*$",
    ]

    earliest: re.Match[str] | None = None

    for pattern in patterns:
        match = re.search(pattern, text)
        if match and (earliest is None or match.start() < earliest.start()):
            earliest = match

    if earliest:
        reply = normalize_text(text[:earliest.start()])
        quoted = normalize_text(text[earliest.start():])
        return reply, quoted

    lines = text.splitlines()
    first_quote_index = next(
        (
            index
            for index, line in enumerate(lines)
            if line.lstrip().startswith(">")
        ),
        None,
    )

    if first_quote_index is not None:
        reply = normalize_text("\n".join(lines[:first_quote_index]))
        quoted = normalize_text("\n".join(lines[first_quote_index:]))
        return reply, quoted

    return text, None


def extract_disclaimer(text: str) -> tuple[str, str | None]:
    patterns = [
        r"(?im)^\s*This email and any attachments.*$",
        r"(?im)^\s*This message may contain confidential.*$",
        r"(?im)^\s*CONFIDENTIALITY NOTICE:.*$",
        r"(?im)^\s*The information contained in this email.*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            disclaimer = normalize_text(text[match.start():])
            cleaned = normalize_text(text[:match.start()])
            return cleaned, disclaimer

    return text, None


def extract_signature(text: str) -> tuple[str, str | None]:
    lines = text.splitlines()

    signature_markers = {
        "best",
        "best regards",
        "regards",
        "kind regards",
        "thanks",
        "thank you",
        "sincerely",
        "cheers",
        "respectfully",
        "v/r",
    }

    for index in range(len(lines) - 1, -1, -1):
        normalized = lines[index].strip().rstrip(",").lower()

        if normalized in signature_markers:
            signature_lines = lines[index:]

            if len(signature_lines) <= 8:
                reply = normalize_text("\n".join(lines[:index]))
                signature = normalize_text("\n".join(signature_lines))
                return reply, signature

    separator_match = re.search(r"(?m)^--\s*$", text)

    if separator_match:
        reply = normalize_text(text[:separator_match.start()])
        signature = normalize_text(text[separator_match.start():])
        return reply, signature

    return text, None


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "replytrim",
    }


@app.post("/v1/clean", response_model=CleanEmailResponse)
def clean_email_reply(
    request: CleanEmailRequest,
    x_rapidapi_proxy_secret: str | None = Header(default=None),
) -> CleanEmailResponse:
    verify_proxy_secret(x_rapidapi_proxy_secret)

    original_content = request.content

    if request.content_type == "html":
        working_text = html_to_text(original_content)
    else:
        working_text = original_content

    working_text = normalize_text(working_text)

    removed_sections: list[str] = []
    signature = None
    quoted_history = None
    disclaimer = None
    mobile_footer = None

    if request.remove_mobile_footer:
        working_text, mobile_footer = extract_mobile_footer(working_text)
        if mobile_footer:
            removed_sections.append("mobile_footer")

    if request.remove_quoted_history:
        working_text, quoted_history = extract_quoted_history(working_text)
        if quoted_history:
            removed_sections.append("quoted_history")

    if request.remove_disclaimer:
        working_text, disclaimer = extract_disclaimer(working_text)
        if disclaimer:
            removed_sections.append("disclaimer")

    if request.remove_signature:
        working_text, signature = extract_signature(working_text)
        if signature:
            removed_sections.append("signature")

    clean_reply = normalize_text(working_text)

    return CleanEmailResponse(
        clean_reply=clean_reply,
        parts=EmailParts(
            reply=clean_reply,
            signature=signature,
            quoted_history=quoted_history,
            disclaimer=disclaimer,
            mobile_footer=mobile_footer,
        ),
        removed_sections=removed_sections,
        input_characters=len(original_content),
        output_characters=len(clean_reply),
    )
