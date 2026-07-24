from __future__ import annotations

import hmac
import ipaddress
import os
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator


API_VERSION = "1.0.0"


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MAX_TEXT_LENGTH = _positive_int_env("MAX_TEXT_LENGTH", 20_000)
MAX_BODY_BYTES = _positive_int_env("MAX_BODY_BYTES", 1_000_000)
RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")


class EntityType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    IPV4 = "ipv4"
    CREDIT_CARD = "credit_card"
    IBAN = "iban"
    JWT = "jwt"
    AWS_ACCESS_KEY = "aws_access_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    SECRET_ASSIGNMENT = "secret_assignment"


class ReplacementMode(str, Enum):
    LABEL = "label"
    FIXED = "fixed"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DetectionRequest(StrictModel):
    text: str = Field(
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Text to inspect. The service does not need to store it.",
    )
    entities: list[EntityType] = Field(
        default_factory=list,
        description="Optional detector allow-list. Omit it to run every detector.",
    )
    @field_validator("entities")
    @classmethod
    def unique_entities(
        cls, value: list[EntityType]
    ) -> list[EntityType]:
        # Preserve caller order while removing duplicates.
        return list(dict.fromkeys(value))




class RedactionRequest(DetectionRequest):
    mode: ReplacementMode = Field(
        default=ReplacementMode.LABEL,
        description="label creates values such as [EMAIL]; fixed uses replacement.",
    )
    replacement: str = Field(
        default="[REDACTED]",
        min_length=1,
        max_length=100,
        description="Replacement used when mode is fixed.",
    )


class MatchResponse(StrictModel):
    type: EntityType
    start: int = Field(ge=0)
    end: int = Field(ge=1)
    confidence: float = Field(ge=0, le=1)


class DetectionResponse(StrictModel):
    total: int = Field(ge=0)
    counts: dict[str, int]
    matches: list[MatchResponse]


class RedactionResponse(DetectionResponse):
    redacted_text: str


class TypeInfo(StrictModel):
    type: EntityType
    description: str


@dataclass(frozen=True, slots=True)
class Candidate:
    type: EntityType
    start: int
    end: int
    confidence: float


EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+\-])"
    r"[A-Z0-9._%+\-]{1,64}@[A-Z0-9.\-]{1,253}\.[A-Z]{2,63}"
    r"(?![A-Z0-9._%+\-])",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PHONE_RE = re.compile(r"(?<![\w+])\+(?:\d[\s().-]?){7,14}\d(?![\w])")
CARD_RE = re.compile(r"(?<![\d+])(?:\d[ -]?){12,18}\d(?!\d)")
IBAN_RE = re.compile(
    r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])",
    re.IGNORECASE,
)
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"
    r"(?![A-Za-z0-9_\-])"
)
AWS_ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})(?![A-Za-z0-9_])"
)
SLACK_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,200}(?![A-Za-z0-9])")
BEARER_TOKEN_RE = re.compile(
    r"\bBearer\s+(?P<value>[A-Za-z0-9._~+/=\-]{10,2048})",
    re.IGNORECASE,
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?P<label>(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----"
    r"[\s\S]{20,10000}?"
    r"-----END (?P=label)-----"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(?:password|passwd|pwd|api[_-]?key|secret|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token)\b\s*[:=]\s*"
    r"(?P<quote>[\"']?)(?P<value>[A-Za-z0-9_./+=:@\-]{6,512})(?P=quote)",
    re.IGNORECASE,
)


TYPE_DESCRIPTIONS: dict[EntityType, str] = {
    EntityType.EMAIL: "Email addresses",
    EntityType.PHONE: "Conservative international phone-number candidates beginning with +",
    EntityType.IPV4: "Valid IPv4 addresses",
    EntityType.CREDIT_CARD: "13–19 digit payment-card candidates that pass Luhn validation",
    EntityType.IBAN: "IBAN candidates that pass the MOD-97 checksum",
    EntityType.JWT: "Three-part JSON Web Token strings",
    EntityType.AWS_ACCESS_KEY: "AWS access-key identifiers beginning with AKIA or ASIA",
    EntityType.GITHUB_TOKEN: "Common GitHub personal, OAuth, user, server, and fine-grained token forms",
    EntityType.SLACK_TOKEN: "Common Slack xox token forms",
    EntityType.BEARER_TOKEN: "Token values following the Bearer authentication scheme",
    EntityType.PRIVATE_KEY: "PEM private-key blocks",
    EntityType.SECRET_ASSIGNMENT: "Values assigned to password, api_key, secret, or token fields",
}


servers = [{"url": PUBLIC_BASE_URL, "description": "Production"}] if PUBLIC_BASE_URL else None
app = FastAPI(
    title="LogShield PII & Secret Redaction API",
    description=(
        "A deterministic text-sanitization API. It returns match positions and never "
        "echoes detected secret values in its match metadata."
    ),
    version=API_VERSION,
    servers=servers,
    docs_url="/docs",
    redoc_url="/redoc",
)
# RapidAPI's request importer documents an OpenAPI 3.0.3 importer. FastAPI defaults
# to a newer OpenAPI version, so advertise 3.0.3 for easier marketplace import.
app.openapi_version = "3.0.3"


@app.middleware("http")
async def protect_rapidapi_routes(request: Request, call_next):
    """Block oversized bodies and, in production, direct calls to /v1 routes."""
    if request.method in {"POST", "PUT", "PATCH"}:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds {MAX_BODY_BYTES} bytes"},
                    )
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})

    if RAPIDAPI_PROXY_SECRET and request.url.path.startswith("/v1/"):
        supplied = request.headers.get("x-rapidapi-proxy-secret", "")
        if not hmac.compare_digest(supplied, RAPIDAPI_PROXY_SECRET):
            return JSONResponse(
                status_code=403,
                content={"detail": "Direct access is disabled; call this API through RapidAPI"},
            )

    response = await call_next(request)
    if request.url.path.startswith("/v1/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_without_echo(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return useful validation errors without echoing submitted text values."""
    del request
    sanitized_errors: list[dict[str, object]] = []
    for error in exc.errors():
        sanitized = {key: value for key, value in error.items() if key not in {"input", "ctx"}}
        sanitized_errors.append(sanitized)
    return JSONResponse(status_code=422, content={"detail": sanitized_errors})


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "name": "LogShield PII & Secret Redaction API",
        "version": API_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "version": API_VERSION}


@app.get(
    "/v1/types",
    response_model=list[TypeInfo],
    tags=["detectors"],
    summary="List supported detector types",
    operation_id="listDetectorTypes",
)
def list_types() -> list[TypeInfo]:
    return [TypeInfo(type=entity, description=TYPE_DESCRIPTIONS[entity]) for entity in EntityType]


@app.post(
    "/v1/detect",
    response_model=DetectionResponse,
    tags=["detectors"],
    summary="Detect PII and credential-like values",
    operation_id="detectSensitiveValues",
)
def detect(payload: DetectionRequest) -> DetectionResponse:
    matches = _detect(payload.text, payload.entities)
    return _detection_response(matches)


@app.post(
    "/v1/redact",
    response_model=RedactionResponse,
    tags=["redaction"],
    summary="Redact detected values from text",
    operation_id="redactSensitiveValues",
)
def redact(payload: RedactionRequest) -> RedactionResponse:
    matches = _detect(payload.text, payload.entities)
    redacted_text = _redact_text(
        payload.text,
        matches,
        mode=payload.mode,
        fixed_replacement=payload.replacement,
    )
    base = _detection_response(matches)
    return RedactionResponse(
        total=base.total,
        counts=base.counts,
        matches=base.matches,
        redacted_text=redacted_text,
    )


def _enabled(entity: EntityType, requested: set[EntityType]) -> bool:
    return not requested or entity in requested


def _regex_candidates(
    text: str,
    pattern: re.Pattern[str],
    entity: EntityType,
    confidence: float,
    group: str | int = 0,
) -> Iterable[Candidate]:
    for match in pattern.finditer(text):
        start, end = match.span(group)
        if start >= 0 and end > start:
            yield Candidate(type=entity, start=start, end=end, confidence=confidence)


def _detect(
    text: str,
    entities: list[EntityType],
) -> list[Candidate]:
    requested = set(entities or [])
    candidates: list[Candidate] = []

    if _enabled(EntityType.PRIVATE_KEY, requested):
        candidates.extend(_regex_candidates(text, PRIVATE_KEY_RE, EntityType.PRIVATE_KEY, 1.0))
    if _enabled(EntityType.GITHUB_TOKEN, requested):
        candidates.extend(_regex_candidates(text, GITHUB_TOKEN_RE, EntityType.GITHUB_TOKEN, 1.0))
    if _enabled(EntityType.AWS_ACCESS_KEY, requested):
        candidates.extend(_regex_candidates(text, AWS_ACCESS_KEY_RE, EntityType.AWS_ACCESS_KEY, 1.0))
    if _enabled(EntityType.SLACK_TOKEN, requested):
        candidates.extend(_regex_candidates(text, SLACK_TOKEN_RE, EntityType.SLACK_TOKEN, 1.0))
    if _enabled(EntityType.JWT, requested):
        candidates.extend(_regex_candidates(text, JWT_RE, EntityType.JWT, 0.99))
    if _enabled(EntityType.BEARER_TOKEN, requested):
        candidates.extend(
            _regex_candidates(text, BEARER_TOKEN_RE, EntityType.BEARER_TOKEN, 0.98, group="value")
        )
    if _enabled(EntityType.CREDIT_CARD, requested):
        for match in CARD_RE.finditer(text):
            raw = match.group(0)
            if _passes_luhn(raw):
                candidates.append(
                    Candidate(EntityType.CREDIT_CARD, match.start(), match.end(), 0.99)
                )
    if _enabled(EntityType.IBAN, requested):
        for match in IBAN_RE.finditer(text):
            raw = match.group(0)
            if _valid_iban(raw):
                candidates.append(Candidate(EntityType.IBAN, match.start(), match.end(), 0.99))
    if _enabled(EntityType.EMAIL, requested):
        candidates.extend(_regex_candidates(text, EMAIL_RE, EntityType.EMAIL, 0.98))
    if _enabled(EntityType.IPV4, requested):
        for match in IPV4_RE.finditer(text):
            try:
                parsed = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if isinstance(parsed, ipaddress.IPv4Address):
                candidates.append(Candidate(EntityType.IPV4, match.start(), match.end(), 0.98))
    if _enabled(EntityType.PHONE, requested):
        for match in PHONE_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if 8 <= len(digits) <= 15 and len(set(digits)) > 1:
                candidates.append(Candidate(EntityType.PHONE, match.start(), match.end(), 0.90))
    if _enabled(EntityType.SECRET_ASSIGNMENT, requested):
        candidates.extend(
            _regex_candidates(
                text,
                SECRET_ASSIGNMENT_RE,
                EntityType.SECRET_ASSIGNMENT,
                0.80,
                group="value",
            )
        )

    return _resolve_overlaps(candidates)


def _resolve_overlaps(candidates: Iterable[Candidate]) -> list[Candidate]:
    """Prefer high-confidence, longer matches when detectors overlap."""
    ranked = sorted(
        set(candidates),
        key=lambda item: (-item.confidence, -(item.end - item.start), item.start, item.type.value),
    )
    selected: list[Candidate] = []
    for candidate in ranked:
        overlaps = any(
            candidate.start < existing.end and existing.start < candidate.end
            for existing in selected
        )
        if not overlaps:
            selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end, item.type.value))


def _passes_luhn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False

    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _valid_iban(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not (compact[:2].isalpha() and compact[2:4].isdigit() and compact.isalnum()):
        return False

    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for character in rearranged:
        expansion = character if character.isdigit() else str(ord(character) - 55)
        for digit in expansion:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def _detection_response(matches: list[Candidate]) -> DetectionResponse:
    counts = Counter(match.type.value for match in matches)
    return DetectionResponse(
        total=len(matches),
        counts=dict(sorted(counts.items())),
        matches=[
            MatchResponse(
                type=match.type,
                start=match.start,
                end=match.end,
                confidence=match.confidence,
            )
            for match in matches
        ],
    )


def _redact_text(
    text: str,
    matches: list[Candidate],
    mode: ReplacementMode,
    fixed_replacement: str,
) -> str:
    if not matches:
        return text

    output: list[str] = []
    cursor = 0
    for match in matches:
        output.append(text[cursor : match.start])
        if mode is ReplacementMode.LABEL:
            output.append(f"[{match.type.value.upper()}]")
        else:
            output.append(fixed_replacement)
        cursor = match.end
    output.append(text[cursor:])
    return "".join(output)
