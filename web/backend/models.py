"""Pydantic models for request / response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


# ── Unified rule representation ──────────────────────────────────────────────

class RuleItem(BaseModel):
    rule_id: str
    title: str
    section: str
    os: str  # "ubuntu" | "windows"
    cis_level: int | None = None
    category: str | None = None
    subcategory: str | None = None
    description: str | None = None
    automated: bool = True
    severity: str | None = None
    tags: list[str] = []


class RulesResponse(BaseModel):
    os: str
    total: int
    sections: dict[str, list[RuleItem]]


# ── Resolve (Hesapla) ────────────────────────────────────────────────────────

class ResolveRequest(BaseModel):
    os: str
    rule_ids: list[str]


class Warning(BaseModel):
    rule_id: str
    message: str
    missing_dependency: str | None = None


class Error(BaseModel):
    rule_id: str
    conflicting_rule: str
    message: str


class ResolveResult(BaseModel):
    valid: bool
    warnings: list[Warning] = []
    errors: list[Error] = []


# ── Generate ──────────────────────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    os: str
    rule_ids: list[str]
    format: Literal["ansible", "bash", "gpo", "powershell"] = "ansible"
    permanent: bool = False


class GenerateResponse(BaseModel):
    success: bool
    message: str
    download_url: str | None = None
    filename: str | None = None
    sha256: str | None = None
    artifact_id: str | None = None


class ArtifactInfoResponse(BaseModel):
    found: bool
    artifact_id: str | None = None
    filename: str | None = None
    sha256: str | None = None
    download_url: str | None = None
