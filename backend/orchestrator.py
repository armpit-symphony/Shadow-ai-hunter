"""
Orchestrator — Shadow AI Hunter
Job orchestration layer that fans out scan requests to worker queues.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from bson import ObjectId
import redis
from rq import Queue

from workers.queue import (
    scan_queue, detection_queue, enrichment_queue, report_queue, get_queue
)
from workers.target_scanner import network_discovery_scan
from workers.ai_usage_detector import run_detection
from workers.enrichment_worker import enrich_scan
from workers.report_engine import create_report

logger = logging.getLogger(__name__)


def now_utc():
    return datetime.now(timezone.utc)


def _get_db():
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
    from pymongo import MongoClient
    client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
    return client, client.shadow_ai_hunter


def _get_redis():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.Redis.from_url(redis_url, decode_responses=True)


# ─── Job Lifecycle ────────────────────────────────────────────────────────────

def create_job(job_data: dict) -> str:
    """
    Create a new scan job record in MongoDB and enqueue to appropriate worker queues.
    Returns the job_id string.
    """
    _client, _db = _get_db()
    try:
        doc = {
            "tenant_id": job_data.get("tenant_id", "default"),
            "job_name": job_data.get("job_name"),
            "target_type": job_data.get("target_type"),
            "target_value": job_data.get("target_value"),
            "modules_enabled": job_data.get("modules_enabled", ["target_scanner"]),
            "status": "queued",
            "results_location": None,
            "metadata": job_data.get("metadata", {}),
            "created_at": now_utc(),
            "started_at": None,
            "completed_at": None,
            "error": None,
            "worker_job_ids": {},  # maps module → RQ job id
        }
        result = _db.scans.insert_one(doc)
        job_id = str(result.inserted_id)
        logger.info(f"[orchestrator] Created job {job_id}")

        # Fan out to appropriate queues based on modules_enabled
        _enqueue_job(job_id, job_data)

        return job_id
    finally:
        _client.close()


def _enqueue_job(job_id: str, job_data: dict) -> None:
    """Enqueue a job to the relevant RQ queues based on module list."""
    tenant_id = job_data.get("tenant_id", "default")
    target_type = job_data.get("target_type")
    target_value = job_data.get("target_value")
    modules = job_data.get("modules_enabled", [])

    redis_conn = _get_redis()

    # Always create a scan_queue entry for any target_type
    if target_type == "network":
        if "target_scanner" in modules:
            q = Queue("scans", connection=redis_conn)
            rq_job = q.enqueue(
                _run_target_scanner_sync,
                job_id,
                target_value,
                tenant_id,
                job_id=job_id,
            )
            _update_worker_job_id(job_id, "target_scanner", rq_job.id)
            logger.info(f"[orchestrator] Enqueued target_scanner for job {job_id}")

    elif target_type in ("url", "api"):
        if "target_scanner" in modules:
            q = Queue("scans", connection=redis_conn)
            rq_job = q.enqueue(
                _run_api_scanner_sync,
                job_id,
                target_value,
                tenant_id,
                job_id=job_id,
            )
            _update_worker_job_id(job_id, "target_scanner", rq_job.id)
            logger.info(f"[orchestrator] Enqueued api_scanner for job {job_id}")

    elif target_type == "repo":
        if "code_analyzer" in modules:
            q = Queue("scans", connection=redis_conn)
            rq_job = q.enqueue(
                _run_code_analyzer_sync,
                job_id,
                target_value,
                tenant_id,
                job_id=job_id,
            )
            _update_worker_job_id(job_id, "code_analyzer", rq_job.id)
            logger.info(f"[orchestrator] Enqueued code_analyzer for job {job_id}")

    if "ai_usage_detector" in modules:
        q = Queue("detection", connection=redis_conn)
        rq_job = q.enqueue(
            _run_ai_detector_sync,
            job_id,
            tenant_id,
            job_id=f"{job_id}_ai_detector",
        )
        _update_worker_job_id(job_id, "ai_usage_detector", rq_job.id)
        logger.info(f"[orchestrator] Enqueued ai_usage_detector for job {job_id}")


def _update_worker_job_id(job_id: str, module: str, rq_job_id: str) -> None:
    try:
        _client, _db = _get_db()
        _db.scans.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {f"worker_job_ids.{module}": rq_job_id}},
        )
        _client.close()
    except Exception as e:
        logger.warning(f"[orchestrator] Could not update worker_job_id: {e}")


# ─── Synchronous Worker Wrappers (called by RQ) ──────────────────────────────

def _run_target_scanner_sync(job_id: str, network_range: str, tenant_id: str) -> dict:
    """Synchronous wrapper for target_scanner — called by RQ."""
    _client, _db = _get_db()
    try:
        _db.scans.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {"status": "running", "started_at": now_utc()}},
        )
    finally:
        _client.close()

    result = network_discovery_scan(network_range, job_id)

    _client, _db = _get_db()
    try:
        _db.scans.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {
                "status": result.get("status", "complete"),
                "completed_at": now_utc(),
                "results_location": f"devices/{job_id}",
                "tenant_id": tenant_id,
            }},
        )
        # Enqueue enrichment after scan
        redis_conn = _get_redis()
        q = Queue("enrichment", connection=redis_conn)
        q.enqueue(_run_enrichment_sync, job_id, tenant_id, job_id=f"{job_id}_enrich")
    finally:
        _client.close()

    return result


def _run_api_scanner_sync(job_id: str, target_url: str, tenant_id: str) -> dict:
    """API scanner stub — placeholder for Phase 3 extension."""
    return {
        "job_id": job_id,
        "status": "complete",
        "target_value": target_url,
        "modules": ["api_scanner"],
        "findings": [],
        "completed_at": now_utc().isoformat(),
    }


def _run_code_analyzer_sync(job_id: str, repo_url: str, tenant_id: str) -> dict:
    """Code analyzer stub — placeholder for Phase 3 extension."""
    return {
        "job_id": job_id,
        "status": "complete",
        "target_value": repo_url,
        "modules": ["code_analyzer"],
        "findings": [],
        "completed_at": now_utc().isoformat(),
    }


def _run_ai_detector_sync(job_id: str, tenant_id: str) -> dict:
    """Run AI usage detector on events associated with this job."""
    _client, _db = _get_db()
    try:
        events = list(_db.events.find({"scan_id": job_id, "tenant_id": tenant_id}))
        _client.close()
    except Exception as e:
        logger.warning(f"[orchestrator] Could not load events for {job_id}: {e}")
        events = []

    result = run_detection(job_id, events)

    _client, _db = _get_db()
    try:
        _db.scans.update_one(
            {"_id": ObjectId(job_id)},
            {"$set": {f"worker_job_ids.ai_usage_detector": "complete"}},
        )
    finally:
        _client.close()

    return result


def _run_enrichment_sync(job_id: str, tenant_id: str) -> dict:
    """Synchronous wrapper for enrichment worker."""
    return enrich_scan(job_id)


# ─── Job Status ──────────────────────────────────────────────────────────────

def get_job(job_id: str) -> Optional[dict]:
    """Get a job by ID. Filters by tenant_id implicitly via callers."""
    _client, _db = _get_db()
    try:
        doc = _db.scans.find_one({"_id": ObjectId(job_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    finally:
        _client.close()


def list_jobs(tenant_id: str = "default", page: int = 1, page_size: int = 20) -> Dict:
    """List jobs for a tenant with pagination."""
    _client, _db = _get_db()
    try:
        query = {"tenant_id": tenant_id}
        total = _db.scans.count_documents(query)
        skip = (page - 1) * page_size
        cursor = (
            _db.scans.find(query)
            .sort("created_at", -1)
            .skip(skip)
            .limit(page_size)
        )
        jobs = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            jobs.append(doc)
        return {"jobs": jobs, "total": total, "page": page, "page_size": page_size}
    finally:
        _client.close()


def cancel_job(job_id: str) -> bool:
    """Attempt to cancel a queued/running job."""
    _client, _db = _get_db()
    try:
        result = _db.scans.update_one(
            {"_id": ObjectId(job_id), "status": {"$in": ["queued", "running"]}},
            {"$set": {"status": "cancelled", "completed_at": now_utc()}},
        )
        if result.modified_count > 0:
            # Attempt to kill RQ job if it was queued
            job = get_job(job_id)
            if job and job.get("worker_job_ids"):
                redis_conn = _get_redis()
                for module, rq_id in job["worker_job_ids"].items():
                    try:
                        q = get_queue(module)
                        q.connection.delete(q.key + rq_id)
                    except Exception:
                        pass
            return True
        return False
    finally:
        _client.close()
