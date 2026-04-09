"""
Job Model — Shadow AI Hunter
Unified scan job schema for the orchestrator layer.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TargetType(str, Enum):
    URL = "url"
    REPO = "repo"
    NETWORK = "network"
    API = "api"


# ─── Pydantic Schemas ────────────────────────────────────────────────────────

class JobCreate(BaseModel):
    """Request body for POST /scan"""
    job_name: Optional[str] = None
    target_type: TargetType
    target_value: str
    modules_enabled: List[str] = Field(default_factory=lambda: ["target_scanner"])
    tenant_id: str = Field(default="default")
    metadata: Optional[dict] = Field(default_factory=dict)


class JobUpdate(BaseModel):
    """PATCH /scan/{id} body"""
    status: Optional[ScanStatus] = None
    metadata: Optional[dict] = None


class JobResponse(BaseModel):
    """GET /scan/{id} response"""
    job_id: str
    job_name: Optional[str]
    tenant_id: str
    target_type: TargetType
    target_value: str
    modules_enabled: List[str]
    status: ScanStatus
    results_location: Optional[str] = None
    metadata: dict
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanListResponse(BaseModel):
    """GET /scans response"""
    jobs: List[JobResponse]
    total: int
    page: int
    page_size: int
