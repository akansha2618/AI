from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.pipeline.orchestrator import FirewallPipeline


BASE_DIR = Path(__file__).resolve().parents[3]
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title="Prompt Injection Firewall",
    description="Rule-based prompt-injection inspection with provenance tracking, policy scoring, and audit logging.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

pipeline = FirewallPipeline()


class DataBlob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(default="external", max_length=200)
    source: str = Field(default="external", max_length=200)
    content: str = Field(max_length=settings.MAX_TEXT_LENGTH)


class ToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(default="tool", max_length=200)
    source: str = Field(default="tool", max_length=200)
    content: str = Field(max_length=settings.MAX_TEXT_LENGTH)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    system_instruction: str | None = Field(default=None, max_length=settings.MAX_TEXT_LENGTH)
    user_input: str = Field(min_length=1, max_length=settings.MAX_TEXT_LENGTH)
    external_data_blobs: list[DataBlob] = Field(default_factory=list, max_length=50)
    tool_outputs: list[ToolOutput] = Field(default_factory=list, max_length=50)


class ResponseScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=200)
    response_text: str = Field(max_length=settings.MAX_TEXT_LENGTH)


async def authorize_api_key(x_api_key: str | None = Header(default=None), authorization: str | None = Header(default=None)) -> None:
    """If API_KEY is configured, require it on API operations (supports X-API-Key or Bearer)."""
    expected = settings.API_KEY
    if not expected:
        return
    supplied = x_api_key or ""
    if not supplied and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="A valid API key is required.")


@app.middleware("http")
async def enforce_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > settings.MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"detail": "Request body is too large."})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
    return await call_next(request)


def decision_payload(decision) -> dict[str, Any]:
    return {
        "request_id": decision.request_id,
        "decision": decision.decision.value,
        "score": decision.score,
        "reason": decision.reason,
        "timestamp": decision.timestamp.isoformat(),
        "findings": [
            {
                "rule": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "source": finding.source.value,
                "location": finding.location,
            }
            for finding in decision.findings
        ],
        "transformations": decision.transformations,
    }


@app.get("/", include_in_schema=False)
async def dashboard():
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="Dashboard asset is missing.")
    return FileResponse(index)


@app.get("/health", tags=["Operations"])
async def health_check():
    return {"status": "healthy", "service": "prompt-injection-firewall", "version": app.version}


@app.get("/api/info", tags=["Operations"], dependencies=[Depends(authorize_api_key)])
async def api_info():
    return {
        "name": app.title,
        "version": app.version,
        "features": ["prompt-injection detection", "provenance tracking", "normalization", "policy scoring", "egress scanning", "audit logging"],
        "limits": {"max_request_bytes": settings.MAX_REQUEST_BYTES, "max_text_length": settings.MAX_TEXT_LENGTH},
        "api_key_required": bool(settings.API_KEY),
    }


@app.post("/analyze", tags=["Analysis"], dependencies=[Depends(authorize_api_key)])
@app.post("/api/analyze", tags=["Analysis"], dependencies=[Depends(authorize_api_key)], include_in_schema=False)
async def analyze_prompt(request: AnalyzeRequest):
    decision = pipeline.process_request(request.model_dump())
    return decision_payload(decision)


@app.post("/response-scan", tags=["Egress"], dependencies=[Depends(authorize_api_key)])
async def scan_model_response(request: ResponseScanRequest):
    safe, finding = pipeline.process_response(request.request_id, request.response_text)
    return {
        "request_id": request.request_id,
        "safe": safe,
        "decision": "ALLOW" if safe else "BLOCK",
        "finding": None if finding is None else {
            "rule": finding.rule_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "source": finding.source.value,
            "location": finding.location,
        },
    }


if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="assets")
