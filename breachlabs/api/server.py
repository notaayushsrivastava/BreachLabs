"""BreachLabs Unified Application Server.

Integrates:
1. Streamable HTTP & SSE MCP Protocol Server at `/mcp`
2. Core Security Assessment REST API at `/api`
3. BreachLabs Interactive Web Application at `/` (and static assets)

API Endpoints:
  POST /api/assessments            create assessment
  GET  /api/assessments/{id}       get assessment
  GET  /api/assessments/{id}/events
  GET  /api/assessments/{id}/findings
  GET  /api/assessments/{id}/report?format=markdown|json
  POST /api/assessments/{id}/cancel
  GET  /api/health                 server health check
  GET  /api/tools                  list registered tools

MCP Endpoints:
  GET  /mcp or /mcp/sse            connect Streamable HTTP / SSE event stream
  POST /mcp or /mcp/messages       send JSON-RPC 2.0 requests
"""

from __future__ import annotations

import os
import threading
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from starlette.middleware.wsgi import WSGIMiddleware

from breachlabs.core.agent import SecurityAgent
from breachlabs.core.types import Assessment, AssessmentStatus, Scope
from breachlabs.mcp.server import mcp_router
from breachlabs.mcp.tools import build_default_registry
from breachlabs.report.generator import generate_json, generate_markdown
from breachlabs.sandbox.manager import LocalSandbox

app = FastAPI(
    title="BreachLabs",
    description="Autonomous AI Application-Security Engineer & Streamable HTTP MCP Server",
    version="0.1.0",
)

# CORS middleware for agent IDEs and web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount MCP Streamable HTTP & SSE Protocol at /mcp
app.include_router(mcp_router, prefix="/mcp")

# In-memory store (MVP; swap for a DB later).
_assessments: dict[str, Assessment] = {}
_lock = threading.Lock()


class CreateAssessmentRequest(BaseModel):
    repository: str  # local path or owner/project; MVP resolves local paths
    commit: str = ""
    mode: str = "deep"
    scope: dict[str, Any] = Field(default_factory=dict)
    port: int = 5000


def _resolve_repo(repository: str) -> str:
    """MVP intake: resolve repository path or demo aliases."""
    if repository.lower() in ("demo", "breachlabs/demo", "breachlabs-demo", "vulnerable_app", "ecommerce"):
        demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo"))
        if os.path.isdir(demo_dir):
            return demo_dir
    path = os.path.abspath(repository)
    if os.path.isdir(path):
        return path
    root_rel = os.path.abspath(os.path.join(os.getcwd(), repository))
    if os.path.isdir(root_rel):
        return root_rel
    raise HTTPException(status_code=400, detail=f"Repository not found: {repository}")


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "BreachLabs Unified Platform",
        "version": "0.1.0",
        "endpoints": {
            "web": "/",
            "api": "/api/assessments",
            "mcp": "/mcp",
        },
    }


@app.get("/api/tools")
def list_api_tools():
    registry = build_default_registry()
    return {"tools": registry.manifests()}


@app.post("/api/demo/run", status_code=201)
def run_demo_attack(background: BackgroundTasks, port: int = 5005):
    """Launch a real live assessment and verification against the sandboxed demo target."""
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo"))
    assessment = Assessment(
        repository="demo/vulnerable_app",
        commit="live-demo",
        mode="deep",  # type: ignore[arg-type]
        scope=Scope(allowed_hosts=["127.0.0.1", "localhost"]),
    )
    with _lock:
        _assessments[assessment.id] = assessment
    background.add_task(_run_assessment, assessment.id, demo_dir, port)
    return assessment.model_dump(mode="json")


@app.post("/api/assessments", status_code=201)
def create_assessment(req: CreateAssessmentRequest, background: BackgroundTasks):
    repo_path = _resolve_repo(req.repository)
    assessment = Assessment(
        repository=req.repository,
        commit=req.commit,
        mode=req.mode,  # type: ignore[arg-type]
        scope=Scope(**req.scope),
    )
    with _lock:
        _assessments[assessment.id] = assessment
    background.add_task(_run_assessment, assessment.id, repo_path, req.port)
    return assessment.model_dump(mode="json")


def _run_assessment(assessment_id: str, repo_path: str, port: int) -> None:
    with _lock:
        assessment = _assessments.get(assessment_id)
    if assessment is None or assessment.status is AssessmentStatus.CANCELLED:
        return
    sandbox = LocalSandbox(repo_path, port=port)
    try:
        sandbox.create()
        sandbox.start()
        agent = SecurityAgent()
        agent.run(assessment, sandbox)
    except Exception as exc:  # noqa: BLE001 - fail the assessment, not the server
        assessment.add_event(f"Assessment error: {exc}")
        assessment.status = AssessmentStatus.FAILED
    finally:
        sandbox.destroy()


@app.get("/api/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    assessment = _get_or_404(assessment_id)
    return assessment.model_dump(mode="json")


@app.get("/api/assessments/{assessment_id}/events")
def get_events(assessment_id: str):
    assessment = _get_or_404(assessment_id)
    return [e.model_dump(mode="json") for e in assessment.events]


@app.get("/api/assessments/{assessment_id}/stream")
async def stream_assessment(assessment_id: str):
    """Stream live assessment events as Server-Sent Events (SSE)."""
    import asyncio
    import json
    from fastapi.responses import StreamingResponse

    assessment = _get_or_404(assessment_id)

    async def event_generator():
        seen = 0
        while True:
            with _lock:
                current_events = list(assessment.events)
                status = assessment.status
                findings = list(assessment.findings)

            while seen < len(current_events):
                event = current_events[seen]
                seen += 1
                payload = {
                    "type": "event",
                    "event": event.model_dump(mode="json"),
                    "status": status.value,
                    "findings_count": len(findings),
                }
                yield f"data: {json.dumps(payload)}\n\n"

            if status in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                with _lock:
                    final_payload = {
                        "type": "complete",
                        "status": status.value,
                        "assessment": assessment.model_dump(mode="json"),
                    }
                yield f"data: {json.dumps(final_payload)}\n\n"
                break

            await asyncio.sleep(0.3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/assessments/{assessment_id}/findings")
def get_findings(assessment_id: str):
    assessment = _get_or_404(assessment_id)
    return [f.model_dump(mode="json") for f in assessment.findings]


@app.get("/api/assessments/{assessment_id}/report")
def get_report(assessment_id: str, format: str = "markdown"):
    assessment = _get_or_404(assessment_id)
    if format == "json":
        return generate_json(assessment)
    return PlainTextResponse(generate_markdown(assessment), media_type="text/markdown")


@app.post("/api/assessments/{assessment_id}/cancel")
def cancel_assessment(assessment_id: str):
    assessment = _get_or_404(assessment_id)
    if assessment.status in (AssessmentStatus.QUEUED, AssessmentStatus.IN_PROGRESS):
        assessment.status = AssessmentStatus.CANCELLED
        assessment.add_event("Assessment cancelled by user")
    return assessment.model_dump(mode="json")


def _get_or_404(assessment_id: str) -> Assessment:
    with _lock:
        assessment = _assessments.get(assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


# Mount the BreachLabs web application at / to serve all pages and static files
try:
    from breachlabs.web.app import create_app

    flask_app = create_app()
    app.mount("/", WSGIMiddleware(flask_app))
except Exception:
    pass


def main() -> None:  # pragma: no cover
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    main()
