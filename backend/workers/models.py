"""
Persistence models and helpers for Shadow AI Hunter detection pipeline.
Connects to MongoDB and provides document schemas + index management.
"""

import os
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.collection import Collection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database connection (same pattern as server.py)
# ---------------------------------------------------------------------------
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
_client: Optional[MongoClient] = None
_db: Optional[Database] = None


def get_db() -> Database:
    """Lazily connect and return the MongoDB database."""
    global _client, _db
    if _db is None:
        _client = MongoClient(MONGO_URL)
        _db = _client.shadow_ai_hunter
        logger.info(f"Workers connected to MongoDB: {MONGO_URL}")
    return _db


def get_collection(name: str) -> Collection:
    return get_db()[name]


# ---------------------------------------------------------------------------
# Collection names
# ---------------------------------------------------------------------------
DETECTIONS_COL = "detections"
FINDINGS_COL = "findings"


# ---------------------------------------------------------------------------
# Detection document schema
# ---------------------------------------------------------------------------
def create_detection_record(
    scan_id: str,
    status: str,
    events_processed: int,
    findings_count: int,
    risk_score: float,
    evidence_hash: str,
    source_project: Optional[str] = None,
    raw_event_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Build a detection document before insertion."""
    return {
        "_id": scan_id,
        "scan_id": scan_id,
        "status": status,                      # queued | running | completed | failed
        "events_processed": events_processed,
        "findings_count": findings_count,
        "risk_score": risk_score,
        "evidence_hash": evidence_hash,
        "source_project": source_project,      # which project sent the telemetry
        "raw_event_ids": raw_event_ids or [],  # list of event _id values from events collection
        "created_at": datetime.utcnow(),
        "completed_at": None,
    }


# ---------------------------------------------------------------------------
# Finding document schema
# ---------------------------------------------------------------------------
def create_finding_record(
    detection_id: str,
    finding_type: str,
    indicator: str,
    severity: str,
    confidence: float,
    service: Optional[str] = None,
    category: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a single finding document before insertion."""
    return {
        "_id": str(uuid4()),
        "detection_id": detection_id,          # FK → detections._id
        "type": finding_type,
        "indicator": indicator,
        "severity": severity,                  # critical | high | medium | low
        "confidence": confidence,
        "service": service,
        "category": category,
        "metadata": metadata or {},
        "created_at": datetime.utcnow(),
    }


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------
def persist_detection(detection: Dict[str, Any]) -> str:
    """Insert or update (upsert) a detection record. Returns the scan_id."""
    col = get_collection(DETECTIONS_COL)
    col.replace_one({"_id": detection["_id"]}, detection, upsert=True)
    return detection["_id"]


def persist_findings(findings: List[Dict[str, Any]]) -> int:
    """Bulk-insert finding documents. Returns count inserted."""
    if not findings:
        return 0
    col = get_collection(FINDINGS_COL)
    col.insert_many(findings)
    return len(findings)


def update_detection_completed(
    scan_id: str,
    risk_score: float,
    findings_count: int,
    evidence_hash: str,
) -> None:
    """Mark a detection as completed with final stats."""
    col = get_collection(DETECTIONS_COL)
    col.update_one(
        {"_id": scan_id},
        {
            "$set": {
                "status": "completed",
                "risk_score": risk_score,
                "findings_count": findings_count,
                "evidence_hash": evidence_hash,
                "completed_at": datetime.utcnow(),
            }
        },
    )


def update_detection_failed(scan_id: str, error: str) -> None:
    """Mark a detection as failed with error message."""
    col = get_collection(DETECTIONS_COL)
    col.update_one(
        {"_id": scan_id},
        {
            "$set": {
                "status": "failed",
                "error": error,
                "completed_at": datetime.utcnow(),
            }
        },
    )


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------
def ensure_indexes() -> None:
    """
    Create indexes for detections and findings collections.
    Safe to call multiple times — indexes are idempotent.
    """
    db = get_db()

    # detections indexes
    db[DETECTIONS_COL].create_index([("status", ASCENDING)])
    db[DETECTIONS_COL].create_index([("created_at", DESCENDING)])
    db[DETECTIONS_COL].create_index([("risk_score", DESCENDING)])
    db[DETECTIONS_COL].create_index([("source_project", ASCENDING)])

    # findings indexes
    db[FINDINGS_COL].create_index([("detection_id", ASCENDING)])
    db[FINDINGS_COL].create_index([("severity", ASCENDING)])
    db[FINDINGS_COL].create_index([("created_at", DESCENDING)])
    db[FINDINGS_COL].create_index([("type", ASCENDING)])

    logger.info("detections + findings indexes ensured")
