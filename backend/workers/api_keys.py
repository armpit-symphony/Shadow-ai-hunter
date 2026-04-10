"""
MongoDB-backed API key store for Shadow AI Hunter.

Keys are stored in the `api_keys` collection and validated against that
MongoDB store. A lightweight in-process cache avoids a MongoDB query on
every request.
"""

import os
import secrets
import time
import logging
from typing import Dict, Optional
from datetime import datetime

from pymongo.collection import Collection

from workers.models import get_db, ASCENDING

logger = logging.getLogger(__name__)

API_KEYS_COL = "api_keys"

# In-memory cache: {key: {"project_id": str, "active": bool, "expires_at": float}}
_api_keys_cache: Optional[Dict[str, dict]] = None
_cache_loaded_at: float = 0.0
_CACHE_TTL_SECONDS: float = 60.0  # Reload from MongoDB every 60 seconds


def _get_api_keys_collection() -> Collection:
    return get_db()[API_KEYS_COL]


def ensure_api_keys_indexes() -> None:
    """Create indexes for the api_keys collection. Idempotent."""
    col = _get_api_keys_collection()
    col.create_index([("api_key", ASCENDING)], unique=True)
    col.create_index([("project_id", ASCENDING)])
    logger.info("api_keys indexes ensured")


def _generate_secure_key(length: int = 32) -> str:
    """Generate a URL-safe random key."""
    return secrets.token_urlsafe(length)


def store_api_key(project_id: str, created_by: Optional[str] = None) -> dict:
    """
    Generate a new API key for project_id and store it in MongoDB.
    Returns the stored document (includes the plaintext key).
    The plaintext key is only returned once — it cannot be retrieved later.
    """
    key = _generate_secure_key()
    doc = {
        "api_key": key,
        "project_id": project_id,
        "created_at": datetime.utcnow(),
        "active": True,
        "created_by": created_by,
    }
    col = _get_api_keys_collection()
    col.insert_one(doc)
    logger.info(f"API key created for project '{project_id}'")
    # Invalidate cache so the new key is immediately valid
    _invalidate_cache()
    return doc


def get_valid_keys() -> Dict[str, dict]:
    """
    Return a dict {api_key: {"project_id": str, "active": bool}}
    for all active keys, using a short TTL cache.
    """
    global _api_keys_cache, _cache_loaded_at
    now = time.monotonic()
    if _api_keys_cache is None or (now - _cache_loaded_at) > _CACHE_TTL_SECONDS:
        _reload_cache()
    return _api_keys_cache or {}


def _reload_cache() -> None:
    """Reload all active keys from MongoDB into the in-process cache."""
    global _api_keys_cache, _cache_loaded_at
    col = _get_api_keys_collection()
    keys = {}
    for doc in col.find({"active": True}, {"api_key": 1, "project_id": 1, "active": 1}):
        keys[doc["api_key"]] = {
            "project_id": doc["project_id"],
            "active": doc.get("active", True),
        }
    _api_keys_cache = keys
    _cache_loaded_at = time.monotonic()
    logger.debug(f"API keys cache reloaded: {len(keys)} active keys")


def _invalidate_cache() -> None:
    """Force the cache to reload on the next lookup."""
    global _api_keys_cache, _cache_loaded_at
    _api_keys_cache = None
    _cache_loaded_at = 0.0


def get_project_for_key(api_key: str) -> Optional[str]:
    """
    Validate api_key and return the bound project_id, or None if invalid/inactive.
    Checks the in-process cache first, then falls back to a direct MongoDB lookup.
    """
    keys = get_valid_keys()
    entry = keys.get(api_key)
    if entry:
        return entry["project_id"]
    # Cache miss — do a direct MongoDB lookup for this specific key
    col = _get_api_keys_collection()
    doc = col.find_one({"api_key": api_key, "active": True})
    if doc:
        # Warm the cache
        _invalidate_cache()
        get_valid_keys()
        return doc["project_id"]
    return None
