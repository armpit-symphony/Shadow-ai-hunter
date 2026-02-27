from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
from datetime import datetime, timedelta, timezone
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from uuid import uuid4
from bson import ObjectId

# Import auth
import auth as auth_module
from auth import (
    User, UserRole, require_admin, require_analyst, require_viewer,
    get_current_active_user, get_password_hash,
    init_db as auth_init_db,
)
from auth_routes import router as auth_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
client = MongoClient(MONGO_URL)
db = client.shadow_ai_hunter

# Collections
scans_collection = db.scans
devices_collection = db.devices
policies_collection = db.policies
alerts_collection = db.alerts
users_collection = db.users
events_collection = db.events
reports_collection = db.reports
lists_collection = db.lists
baselines_collection = db.baselines
ws_events_collection = db.ws_events
audit_logs_collection = db.audit_logs

# Security
security = HTTPBearer()


def _seed_default_users() -> None:
    """
    Create default users on first run if the users collection is empty.
    Passwords are read from environment variables.
    WARNING: Change these before any production deployment.
    """
    admin_pass = os.getenv("DEFAULT_ADMIN_PASSWORD", "changeme-set-in-env")
    analyst_pass = os.getenv("DEFAULT_ANALYST_PASSWORD", "changeme-set-in-env")

    seed_users = [
        {
            "username": "admin",
            "email": "admin@shadowai.local",
            "full_name": "Admin User",
            "role": "admin",
            "hashed_password": get_password_hash(admin_pass),
            "disabled": False,
            "created_at": now_utc(),
        },
        {
            "username": "analyst",
            "email": "analyst@shadowai.local",
            "full_name": "Security Analyst",
            "role": "analyst",
            "hashed_password": get_password_hash(analyst_pass),
            "disabled": False,
            "created_at": now_utc(),
        },
    ]
    try:
        users_collection.insert_many(seed_users)
        logger.warning(
            "Default users seeded. "
            "Set DEFAULT_ADMIN_PASSWORD and DEFAULT_ANALYST_PASSWORD env vars "
            "and change passwords before production use!"
        )
    except Exception as e:
        logger.warning(f"Could not seed default users (may already exist): {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Shadow AI Hunter Backend...")
    try:
        scans_collection.create_index("timestamp")
        devices_collection.create_index("ip_address")
        alerts_collection.create_index("created_at")
        users_collection.create_index("username", unique=True)

        # Inject MongoDB into auth module so get_user() can query it
        auth_init_db(users_collection)

        # Seed default users if the collection is empty
        if users_collection.count_documents({}) == 0:
            _seed_default_users()

        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

    # Start WebSocket event pump
    app.state.ws_task = asyncio.create_task(_ws_event_pump())

    yield

    # Shutdown
    try:
        if getattr(app.state, "ws_task", None):
            app.state.ws_task.cancel()
    except Exception:
        pass
    logger.info("Shutting down Shadow AI Hunter Backend...")
    client.close()


# FastAPI app with lifespan
app = FastAPI(
    title="Shadow AI Hunter API",
    description="Enterprise AI Detection and Network Security Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Basic rate limiting + CSRF protection
# ---------------------------------------------------------------------------

_RATE_LIMITS = {
    ("POST", "/api/auth/login"): (10, 60),
    ("POST", "/api/scan"): (5, 60),
    ("POST", "/api/telemetry/import"): (10, 60),
}
_rate_state: Dict[str, List[float]] = {}
_csrf_allowed = set(
    os.getenv(
        "CSRF_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
)


@app.middleware("http")
async def rate_limit_and_csrf(request: Request, call_next):
    # Rate limiting
    key = (request.method, request.url.path)
    limit = _RATE_LIMITS.get(key)
    if limit:
        max_req, window = limit
        ident = request.client.host if request.client else "unknown"
        bucket_key = f"{ident}:{request.method}:{request.url.path}"
        now = datetime.now().timestamp()
        hits = _rate_state.get(bucket_key, [])
        hits = [t for t in hits if now - t < window]
        if len(hits) >= max_req:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        hits.append(now)
        _rate_state[bucket_key] = hits

    # CSRF for state-changing requests when using cookie auth
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.cookies.get("access_token"):
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            if origin and origin not in _csrf_allowed:
                return JSONResponse({"detail": "CSRF origin denied"}, status_code=403)
            if not origin and referer:
                if not any(referer.startswith(o) for o in _csrf_allowed):
                    return JSONResponse({"detail": "CSRF referer denied"}, status_code=403)
            csrf_cookie = request.cookies.get("csrf_token")
            csrf_header = request.headers.get("x-csrf-token")
            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                return JSONResponse({"detail": "CSRF token invalid"}, status_code=403)

    return await call_next(request)

# Include auth routes (prefix is /api/auth, set in auth_routes.py)
app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _audit_log(action: str, actor: str, target: Optional[str] = None, meta: Optional[Dict] = None) -> None:
    try:
        audit_logs_collection.insert_one({
            "action": action,
            "actor": actor,
            "target": target,
            "meta": meta or {},
            "timestamp": now_utc(),
        })
    except Exception:
        pass

class NetworkScanRequest(BaseModel):
    network_range: str
    scan_type: str = "basic"
    deep_scan: bool = False


class Device(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    device_type: str
    ai_risk_score: float
    ai_services_detected: List[str] = []
    last_seen: datetime
    status: str = "active"


class PolicyRule(BaseModel):
    name: str
    description: str
    rule_type: str
    conditions: Dict[str, Any]
    actions: List[str]
    enabled: bool = True
    created_at: Optional[datetime] = None


class Alert(BaseModel):
    title: str
    description: str
    severity: str
    device_ip: str
    alert_type: str
    created_at: Optional[datetime] = None
    resolved: bool = False


class DashboardStats(BaseModel):
    total_devices: int
    high_risk_devices: int
    active_threats: int
    total_scans: int
    ai_services_blocked: int
    compliance_score: float


class TelemetryImportRequest(BaseModel):
    log_type: str  # "dns" or "proxy"
    entries: List[Dict]


class UserCreateRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    disabled: bool = False


class UserUpdateRequest(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    disabled: Optional[bool] = None
    password: Optional[str] = None


class ListUpdateRequest(BaseModel):
    items: List[str]


class BaselineUpdateRequest(BaseModel):
    known_ai_domains: List[str]


def _user_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(doc["_id"]),
        "username": doc.get("username"),
        "email": doc.get("email"),
        "full_name": doc.get("full_name"),
        "role": doc.get("role", "viewer"),
        "disabled": doc.get("disabled", False),
        "created_at": doc.get("created_at"),
    }


def _normalize_domains(items: List[str]) -> List[str]:
    cleaned = []
    for raw in items:
        val = raw.strip().lower()
        if not val:
            continue
        if val.startswith(".") or val.endswith(".") or ".." in val:
            raise HTTPException(status_code=400, detail=f"Invalid domain: {raw}")
        if not all(c.isalnum() or c in {".", "-", "*"} for c in val):
            raise HTTPException(status_code=400, detail=f"Invalid domain: {raw}")
        if val.count(".") < 1:
            raise HTTPException(status_code=400, detail=f"Invalid domain: {raw}")
        if "*" in val and not val.startswith("*."):
            raise HTTPException(status_code=400, detail=f"Invalid wildcard: {raw}")
        cleaned.append(val)
    # de-dup while preserving order
    seen = set()
    result = []
    for v in cleaned:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead.append(connection)
        for c in dead:
            self.disconnect(c)


manager = ConnectionManager()


async def _ws_event_pump():
    """Poll ws_events collection and broadcast to active WebSocket clients."""
    last_id = None
    while True:
        def _fetch():
            query = {"_id": {"$gt": last_id}} if last_id else {}
            return list(ws_events_collection.find(query).sort("_id", 1).limit(100))

        try:
            events = await asyncio.to_thread(_fetch)
            for ev in events:
                last_id = ev.get("_id")
                payload = {k: v for k, v in ev.items() if k != "_id"}
                await manager.broadcast(json.dumps(payload, default=str))
        except Exception as e:
            logger.error(f"WS event pump error: {e}")

        await asyncio.sleep(0.5)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": now_utc()}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(require_viewer)):
    """Get overall dashboard statistics."""
    try:
        total_devices = devices_collection.count_documents({})
        high_risk_devices = devices_collection.count_documents({"ai_risk_score": {"$gte": 0.7}})
        active_threats = alerts_collection.count_documents(
            {"resolved": False, "severity": {"$in": ["high", "critical"]}}
        )
        total_scans = scans_collection.count_documents({})
        ai_services_blocked = policies_collection.count_documents(
            {"rule_type": "block", "enabled": True}
        )

        compliance_score = max(0.0, 100.0 - (active_threats * 10) - (high_risk_devices * 5))
        compliance_score = min(100.0, compliance_score)

        return DashboardStats(
            total_devices=total_devices,
            high_risk_devices=high_risk_devices,
            active_threats=active_threats,
            total_scans=total_scans,
            ai_services_blocked=ai_services_blocked,
            compliance_score=compliance_score / 100.0,
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard statistics")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@app.get("/api/devices")
async def get_devices(current_user: User = Depends(require_viewer)):
    """Get all detected devices sorted by risk score."""
    try:
        devices = list(devices_collection.find({}).sort("ai_risk_score", -1))
        for d in devices:
            d["id"] = str(d.pop("_id"))
        return {"devices": devices}
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to get devices")


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, current_user: User = Depends(require_viewer)):
    """Get recent alerts, each with a stringified 'id' field."""
    try:
        alerts = list(alerts_collection.find({}).sort("created_at", -1).limit(limit))
        for a in alerts:
            a["id"] = str(a.pop("_id"))
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")


@app.patch("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, current_user: User = Depends(require_analyst)):
    """Mark an alert as resolved. Works with both ObjectId and string _id values."""
    from bson import ObjectId

    # Try ObjectId first (auto-generated), fall back to raw string (custom IDs)
    queries = []
    try:
        queries.append({"_id": ObjectId(alert_id)})
    except Exception:
        pass
    queries.append({"_id": alert_id})

    try:
        for q in queries:
            result = alerts_collection.update_one(
                q,
                {"$set": {
                    "resolved": True,
                    "resolved_at": now_utc(),
                    "resolved_by": current_user.username,
                }},
            )
            if result.matched_count > 0:
                return {"message": "Alert resolved"}
        raise HTTPException(status_code=404, detail="Alert not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        raise HTTPException(status_code=500, detail="Failed to resolve alert")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@app.get("/api/policies")
async def get_policies(current_user: User = Depends(require_viewer)):
    """Get all policy rules."""
    try:
        policies = list(policies_collection.find({}, {"_id": 0}).sort("created_at", -1))
        return {"policies": policies}
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        raise HTTPException(status_code=500, detail="Failed to get policies")


@app.post("/api/policies")
async def create_policy(policy: PolicyRule, current_user: User = Depends(require_analyst)):
    """Create a new policy rule."""
    try:
        policy.created_at = now_utc()
        result = policies_collection.insert_one(policy.dict())
        if result.inserted_id:
            return {"message": "Policy created successfully", "id": str(result.inserted_id)}
        raise HTTPException(status_code=500, detail="Failed to create policy")
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail="Failed to create policy")


# ---------------------------------------------------------------------------
# Users (admin only)
# ---------------------------------------------------------------------------

@app.get("/api/users")
async def list_users(limit: int = 100, current_user: User = Depends(require_admin)):
    """List users. Admin only."""
    try:
        users = list(users_collection.find({}).sort("created_at", -1).limit(limit))
        return {"users": [_user_public(u) for u in users]}
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail="Failed to list users")


@app.post("/api/users")
async def create_user(user: UserCreateRequest, current_user: User = Depends(require_admin)):
    """Create a new user. Admin only."""
    username = user.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    if len(user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    doc = {
        "username": username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role.value if hasattr(user.role, "value") else user.role,
        "disabled": bool(user.disabled),
        "hashed_password": get_password_hash(user.password),
        "created_at": now_utc(),
    }
    try:
        result = users_collection.insert_one(doc)
        doc["_id"] = result.inserted_id
        _audit_log("user:create", current_user.username, target=username, meta={"role": doc["role"]})
        return {"user": _user_public(doc)}
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Username already exists")
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail="Failed to create user")


@app.patch("/api/users/{user_id}")
async def update_user(
    user_id: str,
    updates: UserUpdateRequest,
    current_user: User = Depends(require_admin),
):
    """Update an existing user. Admin only."""
    # Prevent admin from disabling or demoting themselves.
    target = None
    queries = []
    try:
        queries.append({"_id": ObjectId(user_id)})
    except Exception:
        pass
    queries.append({"_id": user_id})

    for q in queries:
        target = users_collection.find_one(q)
        if target:
            break
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if target.get("username") == current_user.username:
        if updates.disabled is True:
            raise HTTPException(status_code=400, detail="You cannot disable your own account")
        if updates.role is not None and updates.role.value != target.get("role"):
            raise HTTPException(status_code=400, detail="You cannot change your own role")

    update_doc: Dict[str, Any] = {}
    if updates.email is not None:
        update_doc["email"] = updates.email
    if updates.full_name is not None:
        update_doc["full_name"] = updates.full_name
    if updates.role is not None:
        update_doc["role"] = updates.role.value if hasattr(updates.role, "value") else updates.role
    if updates.disabled is not None:
        update_doc["disabled"] = bool(updates.disabled)
    if updates.password is not None:
        if len(updates.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        update_doc["hashed_password"] = get_password_hash(updates.password)

    if not update_doc:
        raise HTTPException(status_code=400, detail="No updates provided")

    try:
        users_collection.update_one({"_id": target["_id"]}, {"$set": update_doc})
        updated = users_collection.find_one({"_id": target["_id"]})
        _audit_log("user:update", current_user.username, target=updated.get("username"))
        return {"user": _user_public(updated)}
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user")


# ---------------------------------------------------------------------------
# Allowlist / Denylist (admin only)
# ---------------------------------------------------------------------------

def _get_list_doc(list_id: str) -> Dict[str, Any]:
    doc = lists_collection.find_one({"_id": list_id})
    if not doc:
        return {"_id": list_id, "items": []}
    return doc


@app.get("/api/lists")
async def get_lists(current_user: User = Depends(require_admin)):
    """Get current allowlist and denylist."""
    try:
        allow_doc = _get_list_doc("allowlist")
        deny_doc = _get_list_doc("denylist")
        return {
            "allowlist": allow_doc.get("items", []),
            "denylist": deny_doc.get("items", []),
        }
    except Exception as e:
        logger.error(f"Error getting lists: {e}")
        raise HTTPException(status_code=500, detail="Failed to get lists")


@app.put("/api/lists/allowlist")
async def update_allowlist(payload: ListUpdateRequest, current_user: User = Depends(require_admin)):
    """Replace the allowlist."""
    items = _normalize_domains(payload.items)
    try:
        lists_collection.update_one(
            {"_id": "allowlist"},
            {"$set": {"items": items, "updated_at": now_utc()}},
            upsert=True,
        )
        _audit_log("list:update", current_user.username, target="allowlist", meta={"count": len(items)})
        return {"allowlist": items}
    except Exception as e:
        logger.error(f"Error updating allowlist: {e}")
        raise HTTPException(status_code=500, detail="Failed to update allowlist")


@app.put("/api/lists/denylist")
async def update_denylist(payload: ListUpdateRequest, current_user: User = Depends(require_admin)):
    """Replace the denylist."""
    items = _normalize_domains(payload.items)
    try:
        lists_collection.update_one(
            {"_id": "denylist"},
            {"$set": {"items": items, "updated_at": now_utc()}},
            upsert=True,
        )
        _audit_log("list:update", current_user.username, target="denylist", meta={"count": len(items)})
        return {"denylist": items}
    except Exception as e:
        logger.error(f"Error updating denylist: {e}")
        raise HTTPException(status_code=500, detail="Failed to update denylist")


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------

@app.get("/api/baselines")
async def list_baselines(current_user: User = Depends(require_viewer)):
    """List all baselines."""
    try:
        docs = list(baselines_collection.find({}, {"_id": 0}).sort("segment", 1))
        return {"baselines": docs}
    except Exception as e:
        logger.error(f"Error listing baselines: {e}")
        raise HTTPException(status_code=500, detail="Failed to list baselines")


@app.get("/api/baselines/{segment}")
async def get_baseline(segment: str, current_user: User = Depends(require_viewer)):
    """Get a baseline for a specific network segment."""
    try:
        doc = baselines_collection.find_one({"segment": segment}, {"_id": 0})
        if not doc:
            raise HTTPException(status_code=404, detail="Baseline not found")
        return {"baseline": doc}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting baseline: {e}")
        raise HTTPException(status_code=500, detail="Failed to get baseline")


@app.put("/api/baselines/{segment}")
async def upsert_baseline(
    segment: str,
    payload: BaselineUpdateRequest,
    current_user: User = Depends(require_analyst),
):
    """Create or replace a baseline for a network segment."""
    seg = segment.strip()
    if not seg:
        raise HTTPException(status_code=400, detail="Segment is required")
    domains = _normalize_domains(payload.known_ai_domains)
    doc = {
        "segment": seg,
        "known_ai_domains": domains,
        "updated_at": now_utc(),
    }
    try:
        baselines_collection.update_one(
            {"segment": seg},
            {"$set": doc, "$setOnInsert": {"created_at": now_utc()}},
            upsert=True,
        )
        _audit_log("baseline:upsert", current_user.username, target=seg, meta={"count": len(domains)})
        return {"baseline": doc}
    except Exception as e:
        logger.error(f"Error updating baseline: {e}")
        raise HTTPException(status_code=500, detail="Failed to update baseline")


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def initiate_network_scan(
    scan_request: NetworkScanRequest,
    current_user: User = Depends(require_analyst),
):
    """Start a network scan. Jobs are enqueued to the RQ worker."""
    try:
        scan_id = str(uuid4())
        scan_data = {
            "_id": scan_id,
            "network_range": scan_request.network_range,
            "scan_type": scan_request.scan_type,
            "deep_scan": scan_request.deep_scan,
            "status": "queued",
            "timestamp": now_utc(),
            "devices_found": 0,
            "ai_services_detected": 0,
            "initiated_by": current_user.username,
        }
        scans_collection.insert_one(scan_data)

        # Enqueue to RQ worker
        enqueued = False
        try:
            from workers.queue import scan_queue
            from workers.scanner_worker import network_discovery_scan

            scan_queue.enqueue(
                network_discovery_scan,
                scan_request.network_range,
                scan_id,
                job_id=scan_id,
            )
            enqueued = True
            logger.info(f"[{scan_id}] Scan enqueued to RQ worker")
        except Exception as e:
            logger.warning(f"RQ unavailable, using async fallback: {e}")
            asyncio.create_task(_async_scan_fallback(scan_id, scan_request))

        return {
            "message": "Scan initiated",
            "scan_id": scan_id,
            "status": "queued",
            "worker": "rq" if enqueued else "async-fallback",
        }
    except Exception as e:
        logger.error(f"Error initiating scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate network scan")


async def _async_scan_fallback(scan_id: str, scan_request: NetworkScanRequest):
    """
    Async fallback when RQ worker is unavailable.
    Runs the real scanner_worker function in a thread pool so it doesn't block.
    """
    import asyncio

    loop = asyncio.get_event_loop()
    try:
        from workers.scanner_worker import network_discovery_scan

        await loop.run_in_executor(
            None, network_discovery_scan, scan_request.network_range, scan_id
        )
        await manager.broadcast(
            json.dumps({"type": "scan_completed", "scan_id": scan_id})
        )
    except Exception as e:
        logger.error(f"Async scan fallback failed [{scan_id}]: {e}")
        scans_collection.update_one(
            {"_id": scan_id},
            {"$set": {"status": "failed", "error": str(e)}},
        )


@app.get("/api/scans")
async def get_scans(limit: int = 50, current_user: User = Depends(require_viewer)):
    """Get scan history."""
    try:
        scans = list(scans_collection.find({}).sort("timestamp", -1).limit(limit))
        for s in scans:
            s["id"] = str(s.pop("_id"))
        return {"scans": scans}
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scans")


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: User = Depends(require_viewer)):
    """Get specific scan details including evidence."""
    try:
        scan = scans_collection.find_one({"_id": scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan["id"] = scan_id
        return {"scan": scan}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan")


# ---------------------------------------------------------------------------
# Telemetry ingestion
# ---------------------------------------------------------------------------

@app.post("/api/telemetry/import")
async def import_telemetry(
    import_request: TelemetryImportRequest,
    current_user: User = Depends(require_analyst),
):
    """
    Import telemetry logs (DNS or Proxy) for AI detection analysis.
    Normalizes events, stores them, and enqueues a detection job.
    """
    try:
        import_id = str(uuid4())

        # Store raw entries with import metadata
        tagged_entries = [
            {**e, "_import_id": import_id, "_log_type": import_request.log_type}
            for e in import_request.entries
        ]
        if tagged_entries:
            events_collection.insert_many(tagged_entries)

        # Record the import
        import_record = {
            "_id": import_id,
            "log_type": import_request.log_type,
            "status": "processing",
            "timestamp": now_utc(),
            "entries_count": len(import_request.entries),
            "imported_by": current_user.username,
        }
        scans_collection.insert_one(import_record)

        # Enqueue detection job
        detection_job_id = None
        try:
            from workers.queue import detection_queue
            from workers.detector_worker import run_detection

            job = detection_queue.enqueue(
                run_detection,
                import_id,
                import_request.entries,
                job_id=f"detect-{import_id}",
            )
            detection_job_id = job.id
            scans_collection.update_one(
                {"_id": import_id},
                {"$set": {"status": "queued_detection", "detection_job_id": detection_job_id}},
            )
        except Exception as e:
            logger.warning(f"RQ unavailable for detection job: {e}")
            scans_collection.update_one(
                {"_id": import_id},
                {"$set": {"status": "completed", "completed_at": now_utc()}},
            )

        return {
            "message": "Telemetry imported successfully",
            "import_id": import_id,
            "entries_processed": len(import_request.entries),
            "detection_job_id": detection_job_id,
            "status": "processing",
        }
    except Exception as e:
        logger.error(f"Error importing telemetry: {e}")
        raise HTTPException(status_code=500, detail="Failed to import telemetry")


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.post("/api/reports/generate")
async def generate_report(
    scan_id: str,
    fmt: str = "json",
    current_user: User = Depends(require_analyst),
):
    """Generate a security report for a completed scan."""
    try:
        scan = scans_collection.find_one({"_id": scan_id})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = list(alerts_collection.find({"scan_id": scan_id}, {"_id": 0}))

        report_id = str(uuid4())
        try:
            from workers.report_worker import create_report

            report_data = create_report(scan_id, scan, findings, format=fmt)
            # Store report metadata
            reports_collection.insert_one({
                "_id": report_id,
                "scan_id": scan_id,
                "format": fmt,
                "generated_by": current_user.username,
                "generated_at": now_utc(),
                "findings_count": len(findings),
            })
            return {
                "report_id": report_id,
                "scan_id": scan_id,
                "format": fmt,
                "report": report_data.get("content") if fmt == "json" else None,
                "message": "Report generated successfully",
            }
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in report endpoint: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@app.get("/api/reports")
async def list_reports(current_user: User = Depends(require_viewer)):
    """List generated reports."""
    try:
        rpts = list(reports_collection.find({}, {"_id": 0}).sort("generated_at", -1).limit(50))
        return {"reports": rpts}
    except Exception as e:
        logger.error(f"Error listing reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to list reports")


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time scan/alert updates."""
    token = websocket.query_params.get("token") or websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=1008)
        return
    try:
        payload = auth_module.jwt.decode(
            token,
            auth_module.SECRET_KEY,
            algorithms=[auth_module.ALGORITHM],
        )
        username = payload.get("sub")
        user = auth_module.get_user(username) if username else None
        if not user or user.disabled:
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Demo data (admin only)
# ---------------------------------------------------------------------------

@app.get("/api/demo/populate")
async def populate_demo_data(current_user: User = Depends(require_admin)):
    """Populate database with demo data. Admin only."""
    try:
        devices_collection.delete_many({})
        alerts_collection.delete_many({})
        policies_collection.delete_many({})

        demo_devices = [
            {
                "ip_address": "10.0.1.100",
                "hostname": "exec-laptop-01",
                "device_type": "laptop",
                "ai_risk_score": 0.95,
                "ai_services_detected": ["openai-gpt4", "claude-3", "midjourney"],
                "evidence": [
                    {"type": "telemetry_dns", "indicator": "api.openai.com", "severity": "high"},
                    {"type": "telemetry_dns", "indicator": "api.anthropic.com", "severity": "high"},
                ],
                "last_seen": now_utc(),
                "status": "active",
            },
            {
                "ip_address": "10.0.1.150",
                "hostname": "dev-workstation",
                "device_type": "workstation",
                "ai_risk_score": 0.75,
                "ai_services_detected": ["github-copilot", "codeium"],
                "evidence": [
                    {"type": "telemetry_proxy", "indicator": "copilot-proxy.githubusercontent.com",
                     "severity": "medium"},
                ],
                "last_seen": now_utc(),
                "status": "active",
            },
            {
                "ip_address": "10.0.1.200",
                "hostname": "ml-server-prod",
                "device_type": "ml-server",
                "ai_risk_score": 0.85,
                "ai_services_detected": ["tensorflow", "pytorch", "huggingface"],
                "evidence": [
                    {"type": "open_ai_port", "port": 8501, "service": "TensorFlow Serving REST",
                     "severity": "high"},
                    {"type": "open_ai_port", "port": 8888, "service": "Jupyter Notebook",
                     "severity": "medium"},
                ],
                "last_seen": now_utc(),
                "status": "active",
            },
        ]
        devices_collection.insert_many(demo_devices)

        demo_policies = [
            {
                "name": "Block Unauthorized LLM APIs",
                "description": "Block access to external LLM API endpoints not on the approved list",
                "rule_type": "block",
                "conditions": {"categories": ["llm"], "allowlist_bypass": False},
                "actions": ["block_network", "send_alert", "log_activity"],
                "enabled": True,
                "created_at": now_utc(),
            },
            {
                "name": "Monitor High-Risk Devices",
                "description": "Alert on devices with AI risk score >= 0.8",
                "rule_type": "monitor",
                "conditions": {"ai_risk_score": {"$gte": 0.8}},
                "actions": ["send_alert", "log_activity"],
                "enabled": True,
                "created_at": now_utc(),
            },
            {
                "name": "Audit Local AI Services",
                "description": "Flag any device running a local LLM service (Ollama, LocalAI, etc.)",
                "rule_type": "audit",
                "conditions": {"open_ai_ports": True},
                "actions": ["send_alert", "require_approval"],
                "enabled": True,
                "created_at": now_utc(),
            },
        ]
        policies_collection.insert_many(demo_policies)

        demo_alerts = [
            {
                "title": "Critical: Unauthorized AI Usage — exec-laptop-01",
                "description": (
                    "Executive laptop (10.0.1.100) is accessing multiple external AI services "
                    "without IT approval: openai-gpt4, claude-3, midjourney."
                ),
                "severity": "critical",
                "device_ip": "10.0.1.100",
                "alert_type": "policy_violation",
                "evidence": [
                    {"type": "telemetry_dns", "indicator": "api.openai.com", "confidence": 0.95},
                ],
                "created_at": now_utc(),
                "resolved": False,
            },
            {
                "title": "High: Unmanaged ML Server Detected",
                "description": (
                    "ml-server-prod (10.0.1.200) has TensorFlow Serving and Jupyter Notebook "
                    "exposed on the network with no registered IT asset record."
                ),
                "severity": "high",
                "device_ip": "10.0.1.200",
                "alert_type": "ai_service_discovered",
                "evidence": [
                    {"type": "open_ai_port", "port": 8501, "severity": "high"},
                ],
                "created_at": now_utc() - timedelta(hours=2),
                "resolved": False,
            },
        ]
        alerts_collection.insert_many(demo_alerts)

        return {"message": "Demo data populated successfully"}
    except Exception as e:
        logger.error(f"Error populating demo data: {e}")
        raise HTTPException(status_code=500, detail="Failed to populate demo data")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
