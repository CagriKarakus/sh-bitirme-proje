"""Rules router – rule listing, conflict resolution, and config generation."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from models import (
    GenerateRequest,
    GenerateResponse,
    ResolveRequest,
    ResolveResult,
    RulesResponse,
)
from services.rule_loader import load_rules_grouped
from services.resolver import resolve
from services.generator import generate, get_artifact_path

router = APIRouter(prefix="/api", tags=["rules"])


@router.get("/rules/{os_name}", response_model=RulesResponse)
async def get_rules(os_name: str):
    """Return all rules for the given OS, grouped by section."""
    if os_name not in ("ubuntu", "windows"):
        raise HTTPException(status_code=400, detail=f"Desteklenmeyen OS: {os_name}")

    grouped = load_rules_grouped(os_name)
    total = sum(len(v) for v in grouped.values())
    return RulesResponse(os=os_name, total=total, sections=grouped)


@router.post("/resolve", response_model=ResolveResult)
async def resolve_rules(req: ResolveRequest):
    """Validate selected rules for dependency / conflict issues."""
    if req.os not in ("ubuntu", "windows"):
        raise HTTPException(status_code=400, detail=f"Desteklenmeyen OS: {req.os}")

    if not req.rule_ids:
        raise HTTPException(status_code=400, detail="En az bir kural seçilmelidir.")

    return resolve(req.os, req.rule_ids)


@router.post("/generate", response_model=GenerateResponse)
async def generate_config(req: GenerateRequest):
    """Generate configuration artifact for the selected rules."""
    if req.os not in ("ubuntu", "windows"):
        raise HTTPException(status_code=400, detail=f"Desteklenmeyen OS: {req.os}")

    if not req.rule_ids:
        raise HTTPException(status_code=400, detail="En az bir kural seçilmelidir.")

    result = generate(req.os, req.rule_ids, req.format)

    if not result.get("success"):
        return GenerateResponse(
            success=False,
            message=result.get("message", "Bilinmeyen hata"),
        )

    artifact_id = result["artifact_id"]
    return GenerateResponse(
        success=True,
        message=result["message"],
        download_url=f"/api/download/{artifact_id}",
        filename=result["filename"],
        sha256=result["sha256"],
    )


@router.get("/download/{artifact_id}")
async def download_artifact(artifact_id: str):
    """Serve a generated artifact file for download."""
    # Sanitize: only allow hex characters
    if not artifact_id.isalnum():
        raise HTTPException(status_code=400, detail="Geçersiz artifact ID")

    file_path = get_artifact_path(artifact_id)
    if not file_path or not file_path.exists():
        raise HTTPException(status_code=404, detail="Artifact bulunamadı")

    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type="application/octet-stream",
    )
