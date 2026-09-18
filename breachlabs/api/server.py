"""Assessment API (PRD.md section 17).

POST /api/assessments            create assessment
GET  /api/assessments/{id}       get assessment
GET  /api/assessments/{id}/events
GET  /api/assessments/{id}/findings
GET  /api/assessments/{id}/report?format=markdown|json
POST /api/assessments/{id}/cancel
"""

from __future__ import annotations

import os
import threading
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from breachlabs.core.agent import SecurityAgent
from breachlabs.core.types import Assessment, AssessmentStatus, Scope
from breachlabs.report.generator import generate_json, generate_markdown
from breachlabs.sandbox.manager import LocalSandbox

app = FastAPI(title="BreachLabs", version="0.1.0")

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
    """MVP intake: resolve a local path. Git clone support arrives post-MVP."""
    path = os.path.abspath(repository)
    if os.path.isdir(path):
        return path
    raise HTTPException(status_code=400, detail=f"Repository not found: {repository}")


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


def main() -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
