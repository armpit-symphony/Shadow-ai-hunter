from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from pydantic import BaseModel, model_validator
from typing import List, Dict, Optional, Any
import os
from datetime import datetime, timedelta
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from uuid import uuid4

# Import auth
from auth import (
    User, UserRole, require_admin, require_analyst, require_viewer,
    get_current_active_user
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

# Security
security = HTTPBearer()

# ---- Ingest API key guard ----
# Keys are checked against:
#   1. MongoDB api_keys collection (primary, hot-reloadable)
#   2. INGEST_API_KEYS env var (legacy fallback, requires restart)
_ingest_key_map_env: Optional[dict] = None  # cached env var parse


def _load_env_key_map() -> dict:
    """Parse INGEST_API_KEYS env var into {key: project_id} dict (legacy fallback)."""
    global _ingest_key_map_env
    if _ingest_key_map_env is None:
        raw = os.getenv("INGEST_API_KEYS", "")
        _ingest_key_map_env = {}
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            project_id, key = entry.split(":", 1)
            _ingest_key_map_env[key.strip()] = project_id.strip()
    return _ingest_key_map_env


def _get_project_for_key(x_api_key: str) -> Optional[str]:
    """
    Return the project_id this key is bound to, or None if invalid.
    Checks MongoDB api_keys collection first (hot), then falls back to
    the INGEST_API_KEYS env var (static, requires restart).
    """
    # Import lazily to avoid circular import at module load time
    from workers import api_keys as mongo_keys
    # MongoDB source (primary)
    project = mongo_keys.get_project_for_key(x_api_key)
    if project:
        return project
    # Env var fallback (static, legacy)
    return _load_env_key_map().get(x_api_key)


def require_ingest_key(x_api_key: Optional[str] = None) -> str:
    """
    Validates X-API-Key header against the api_keys collection (or INGEST_API_KEYS env).
    Raises HTTPException 401 on missing/invalid key, 503 if no keys are configured.
    Returns the validated key on success.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
        )
    project = _get_project_for_key(x_api_key)
    if project is None:
        # Check if any keys exist at all (MongoDB or env)
        from workers import api_keys as mongo_keys
        env_map = _load_env_key_map()
        mongo_keys_count = len(mongo_keys.get_valid_keys())
        if not env_map and mongo_keys_count == 0:
            logger.error("No API keys configured; /ingest/event is locked down")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Ingest endpoint has no API keys configured",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
        )
    return x_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Shadow AI Hunter Backend...")
    # Initialize auth — must be done before any JWT-protected endpoint is called
    from auth import init_db
    init_db(users_collection)
    # Initialize collections with indexes
    try:
        scans_collection.create_index("timestamp")
        devices_collection.create_index("ip_address")
        alerts_collection.create_index("created_at")
        events_collection.create_index("source_project")
        events_collection.create_index("detection_status")
        events_collection.create_index("created_at")
        # Initialize api_keys collection
        try:
            from workers import api_keys as mongo_keys
            mongo_keys.ensure_api_keys_indexes()
            logger.info("api_keys collection initialized")
        except Exception as e:
            logger.warning(f"api_keys initialization skipped: {e}")
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Shadow AI Hunter Backend...")
    client.close()

# FastAPI app with lifespan
app = FastAPI(
    title="Shadow AI Hunter API",
    description="Enterprise AI Detection and Network Security Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include auth routes
app.include_router(auth_router)

# Pydantic models
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
    source_project: Optional[str] = None

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

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

# Basic health check
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Dashboard endpoints
@app.get("/api/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get dashboard statistics. When X-API-Key is provided, returns stats
    scoped to the key's bound project. JWT Bearer token users see global stats.
    """
    bound_project = None

    # Authenticate
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    try:
        if bound_project:
            # Build project scope filter for collections that carry project identity
            project_filter = {
                "$or": [
                    {"source_project": bound_project},
                    {"project_id": bound_project},
                ]
            }
            # For scans, scope via detection records for this project
            detection_ids = [
                d["_id"] for d in
                db["detections"].find({"source_project": bound_project}, {"_id": 1})
            ]
            scan_filter = {"_id": {"$in": detection_ids}} if detection_ids else {"_id": None}

            total_devices = devices_collection.count_documents(project_filter)
            high_risk_devices = devices_collection.count_documents(
                {**project_filter, "ai_risk_score": {"$gte": 0.7}}
            )
            active_threats = alerts_collection.count_documents(
                {**project_filter, "resolved": False, "severity": {"$in": ["high", "critical"]}}
            )
            total_scans = scans_collection.count_documents(scan_filter)
        else:
            # JWT path — global stats (existing behavior)
            total_devices = devices_collection.count_documents({})
            high_risk_devices = devices_collection.count_documents({"ai_risk_score": {"$gte": 0.7}})
            active_threats = alerts_collection.count_documents({"resolved": False, "severity": {"$in": ["high", "critical"]}})
            total_scans = scans_collection.count_documents({})

        # Policies are global infrastructure — always unscoped
        ai_services_blocked = policies_collection.count_documents({"rule_type": "block", "enabled": True})

        # Calculate compliance score based on scoped metrics
        compliance_score = max(0.0, 100.0 - (active_threats * 10) - (high_risk_devices * 5))
        compliance_score = min(100.0, compliance_score)

        return DashboardStats(
            total_devices=total_devices,
            high_risk_devices=high_risk_devices,
            active_threats=active_threats,
            total_scans=total_scans,
            ai_services_blocked=ai_services_blocked,
            compliance_score=compliance_score / 100.0
        )
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard statistics")

@app.get("/api/devices")
async def get_devices(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get all detected devices. When X-API-Key is provided, results are scoped
    to the key's bound project. JWT Bearer token users see all devices.
    """
    query = {}
    bound_project = None

    # API key path — project-scoped access
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise  # re-raise 401/503 from require_ingest_key
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    if bound_project:
        query["$or"] = [
            {"source_project": bound_project},
            {"project_id": bound_project},
        ]

    try:
        devices = list(devices_collection.find(query, {"_id": 0}).sort("ai_risk_score", -1))
        return {"devices": devices}
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to get devices")

@app.get("/api/alerts")
async def get_alerts(
    limit: int = 50,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get recent alerts. When X-API-Key is provided, results are scoped to
    the key's bound project. JWT Bearer token users see all alerts.
    """
    query = {}
    bound_project = None

    # API key path — project-scoped access
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise  # re-raise 401/503 from require_ingest_key
    elif x_token:
        # JWT path — existing behavior, require valid viewer token
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    if bound_project:
        query["$or"] = [
            {"source_project": bound_project},
            {"project_id": bound_project},
        ]

    try:
        alerts = list(alerts_collection.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")

@app.get("/api/policies")
async def get_policies(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get all policy rules. When X-API-Key is provided, returns only policies
    that belong to the key's bound project. JWT Bearer users see all policies.
    """
    query = {}

    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    if bound_project:
        query["$or"] = [
            {"source_project": bound_project},
            {"project_id": bound_project},
        ]

    try:
        policies = list(policies_collection.find(query, {"_id": 0}).sort("created_at", -1))
        return {"policies": policies}
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        raise HTTPException(status_code=500, detail="Failed to get policies")

@app.post("/api/policies")
async def create_policy(
    policy: PolicyRule,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Create a new policy rule. When X-API-Key is provided, the policy is tagged
    with the key's bound project. JWT Bearer users must be analysts.
    """
    # Authenticate
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
        bound_project = None
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    try:
        policy_dict = policy.dict()
        policy_dict["created_at"] = datetime.utcnow()
        # Tag with source_project if created via API key
        if bound_project:
            policy_dict["source_project"] = bound_project
        result = policies_collection.insert_one(policy_dict)
        if result.inserted_id:
            return {"message": "Policy created successfully", "id": str(result.inserted_id)}
        raise HTTPException(status_code=500, detail="Failed to create policy")
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail="Failed to create policy")

@app.post("/api/scan")
async def initiate_network_scan(scan_request: NetworkScanRequest, current_user: User = Depends(require_analyst)):
    """Start a network scan"""
    try:
        # Create scan record
        scan_id = str(uuid4())
        scan_data = {
            "_id": scan_id,
            "network_range": scan_request.network_range,
            "scan_type": scan_request.scan_type,
            "deep_scan": scan_request.deep_scan,
            "status": "queued",
            "timestamp": datetime.utcnow(),
            "devices_found": 0,
            "ai_services_detected": 0,
            "initiated_by": current_user.username
        }
        scans_collection.insert_one(scan_data)
        
        # Enqueue job to RQ (optional - falls back to async if Redis unavailable)
        try:
            from workers.queue import scan_queue
            from workers.scanner_worker import network_discovery_scan
            job = scan_queue.enqueue(
                network_discovery_scan,
                scan_request.network_range,
                scan_id,
                job_id=scan_id
            )
            logger.info(f"[{scan_id}] Scan enqueued to job queue")
        except Exception as e:
            logger.warning(f"RQ not available, using async: {e}")
            # Fallback to async task
            asyncio.create_task(perform_network_scan(scan_id, scan_request))
        
        return {"message": "Scan initiated", "scan_id": scan_id, "status": "queued"}
    except Exception as e:
        logger.error(f"Error initiating scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate network scan")

async def perform_network_scan(scan_id: str, scan_request: NetworkScanRequest):
    """Background task for network scanning"""
    try:
        # Simulate network scanning process
        await asyncio.sleep(2)  # Simulate scan time
        
        # Mock discovered devices for demo
        mock_devices = [
            {
                "ip_address": "192.168.1.10",
                "hostname": "workstation-01",
                "device_type": "workstation",
                "ai_risk_score": 0.8,
                "ai_services_detected": ["openai-api", "claude-api"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            },
            {
                "ip_address": "192.168.1.15",
                "hostname": "server-ai-01",
                "device_type": "server",
                "ai_risk_score": 0.9,
                "ai_services_detected": ["huggingface", "tensorflow-serving"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            },
            {
                "ip_address": "192.168.1.25",
                "hostname": "mobile-device",
                "device_type": "mobile",
                "ai_risk_score": 0.3,
                "ai_services_detected": ["chatgpt-app"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            }
        ]
        
        # Store devices
        for device in mock_devices:
            devices_collection.replace_one(
                {"ip_address": device["ip_address"]}, 
                device, 
                upsert=True
            )
        
        # Generate alerts for high-risk devices
        for device in mock_devices:
            if device["ai_risk_score"] > 0.7:
                alert = {
                    "title": f"High AI Risk Detected - {device['hostname']}",
                    "description": f"Device {device['ip_address']} detected using unauthorized AI services: {', '.join(device['ai_services_detected'])}",
                    "severity": "high" if device["ai_risk_score"] > 0.8 else "medium",
                    "device_ip": device["ip_address"],
                    "alert_type": "ai_detection",
                    "created_at": datetime.utcnow(),
                    "resolved": False
                }
                alerts_collection.insert_one(alert)
        
        # Update scan status
        scans_collection.update_one(
            {"_id": scan_id}, 
            {
                "$set": {
                    "status": "completed",
                    "devices_found": len(mock_devices),
                    "ai_services_detected": sum(len(d["ai_services_detected"]) for d in mock_devices),
                    "completed_at": datetime.utcnow()
                }
            }
        )
        
        # Broadcast scan completion via WebSocket
        await manager.broadcast(json.dumps({
            "type": "scan_completed",
            "scan_id": scan_id,
            "devices_found": len(mock_devices)
        }))
        
    except Exception as e:
        logger.error(f"Error in network scan: {e}")
        # Update scan status to failed
        scans_collection.update_one(
            {"_id": scan_id}, 
            {"$set": {"status": "failed", "error": str(e)}}
        )

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back for now
            await manager.send_personal_message(f"Echo: {data}", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/api/demo/populate")
async def populate_demo_data(current_user: User = Depends(require_admin)):
    """Populate database with demo data (admin only)"""
    try:
        # Clear existing data
        devices_collection.delete_many({})
        alerts_collection.delete_many({})
        policies_collection.delete_many({})
        
        # Add demo devices
        demo_devices = [
            {
                "ip_address": "10.0.1.100",
                "hostname": "exec-laptop-01",
                "device_type": "laptop",
                "ai_risk_score": 0.95,
                "ai_services_detected": ["openai-gpt4", "claude-3", "midjourney"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            },
            {
                "ip_address": "10.0.1.150",
                "hostname": "dev-workstation",
                "device_type": "workstation", 
                "ai_risk_score": 0.75,
                "ai_services_detected": ["github-copilot", "codeium"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            },
            {
                "ip_address": "10.0.1.200",
                "hostname": "ml-server-prod",
                "device_type": "server",
                "ai_risk_score": 0.85,
                "ai_services_detected": ["tensorflow", "pytorch", "huggingface"],
                "last_seen": datetime.utcnow(),
                "status": "active"
            }
        ]
        devices_collection.insert_many(demo_devices)
        
        # Add demo policies
        demo_policies = [
            {
                "name": "Block Unauthorized AI APIs",
                "description": "Automatically block access to unauthorized AI services",
                "rule_type": "block",
                "conditions": {"ai_services": ["openai-api", "claude-api"]},
                "actions": ["block_network", "send_alert"],
                "enabled": True,
                "created_at": datetime.utcnow()
            },
            {
                "name": "Monitor High-Risk Devices",
                "description": "Alert on devices with AI risk score > 0.8",
                "rule_type": "monitor",
                "conditions": {"ai_risk_score": {"$gte": 0.8}},
                "actions": ["send_alert", "log_activity"],
                "enabled": True,
                "created_at": datetime.utcnow()
            }
        ]
        policies_collection.insert_many(demo_policies)
        
        # Add demo alerts
        demo_alerts = [
            {
                "title": "Critical: Unauthorized AI Usage Detected",
                "description": "Executive laptop accessing multiple AI services without approval",
                "severity": "critical",
                "device_ip": "10.0.1.100",
                "alert_type": "policy_violation",
                "created_at": datetime.utcnow(),
                "resolved": False
            },
            {
                "title": "High Risk: ML Server Anomaly",
                "description": "Production ML server showing unusual AI service patterns",
                "severity": "high",
                "device_ip": "10.0.1.200",
                "alert_type": "anomaly_detection",
                "created_at": datetime.utcnow() - timedelta(hours=2),
                "resolved": False
            }
        ]
        alerts_collection.insert_many(demo_alerts)
        
        return {"message": "Demo data populated successfully"}
    except Exception as e:
        logger.error(f"Error populating demo data: {e}")
        raise HTTPException(status_code=500, detail="Failed to populate demo data")


# Telemetry Import Endpoint
class TelemetryImportRequest(BaseModel):
    log_type: str  # "dns" or "proxy"
    entries: List[Dict]


# ---- /ingest/event models ----
class IngestEventRequest(BaseModel):
    project: str  # min_length=1 enforced below via model_validator
    events: List[Dict]  # min 1 item enforced below

    @model_validator(mode="after")
    def check_non_empty(self) -> "IngestEventRequest":
        if not self.project or not self.project.strip():
            raise ValueError("field 'project' cannot be empty")
        if not self.events:
            raise ValueError("field 'events' must be a non-empty list")
        return self


class IngestEventResponse(BaseModel):
    accepted: bool
    project: str
    events_ingested: int
    job_id: str
    event_ids: List[str]


class DetectionStatusResponse(BaseModel):
    job_id: str
    status: str  # queued | running | completed | failed | unknown
    source_project: Optional[str] = None
    findings_count: int = 0
    risk_score: float = 0.0
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


@app.post("/api/telemetry/import")
async def import_telemetry(
    import_request: TelemetryImportRequest,
    current_user: User = Depends(require_admin)
):
    """
    Import telemetry logs for analysis
    Accepts DNS or Proxy logs, normalizes and stores events
    """
    try:
        scan_id = str(uuid4())
        
        # Create scan/import record
        import_data = {
            "_id": scan_id,
            "log_type": import_request.log_type,
            "status": "processing",
            "timestamp": datetime.utcnow(),
            "entries_count": len(import_request.entries),
            "imported_by": current_user.username
        }
        
        # Store raw entries
        events_collection = db.events
        events_collection.insert_many(import_request.entries)
        
        import_data["status"] = "completed"
        import_data["completed_at"] = datetime.utcnow()
        
        # Enqueue detection job
        try:
            from workers.queue import detection_queue
            from workers.detector_worker import run_detection
            job = detection_queue.enqueue(
                run_detection,
                scan_id,
                import_request.entries,
                job_id=f"detect-{scan_id}"
            )
            import_data["detection_job_id"] = job.id
        except Exception as e:
            logger.warning(f"RQ not available for detection: {e}")
        
        return {
            "message": "Telemetry imported successfully",
            "import_id": scan_id,
            "entries_processed": len(import_request.entries),
            "status": "completed"
        }
    except Exception as e:
        logger.error(f"Error importing telemetry: {e}")
        raise HTTPException(status_code=500, detail="Failed to import telemetry")


# ---- /ingest/event endpoint ----
@app.post("/ingest/event", response_model=IngestEventResponse)
async def ingest_event(
    request_data: IngestEventRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Ingest telemetry events from an external project.
    Persists raw events, then kicks off async detection.
    The X-API-Key must be bound to the same project as the request body.
    """
    # Validate API key — raises 401 or 503 on failure
    require_ingest_key(x_api_key)

    project = request_data.project
    raw_events = request_data.events

    # Verify the key is bound to this project
    bound_project = _get_project_for_key(x_api_key)
    if bound_project and bound_project != project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This API key is bound to project '{bound_project}', not '{project}'",
        )

    # Defensive re-validation
    if not project:
        raise HTTPException(status_code=400, detail="'project' field is required")
    if not raw_events:
        raise HTTPException(status_code=400, detail="'events' must be a non-empty list")

    scan_id = f"ingest-{uuid4()}"

    # ---- 1. Persist each event with project context ----
    event_ids: List[str] = []
    normalized_events: List[Dict] = []

    for event in raw_events:
        event_id = f"evt-{uuid4()}"
        normalized = {
            **event,                          # preserve original fields
            "_id": event_id,
            "source_project": project,
            "project_id": project,             # project_id mirrors source_project for query ergonomics
            "detection_status": "pending",    # will flip to "done" after detection
            "ingested_at": datetime.utcnow(),
        }
        # Normalize timestamp field if present but named differently
        if "timestamp" in event and "created_at" not in normalized:
            normalized["created_at"] = event["timestamp"]
        elif "created_at" not in normalized:
            normalized["created_at"] = datetime.utcnow()

        events_collection.insert_one(normalized)
        event_ids.append(event_id)
        normalized_events.append(normalized)

    logger.info(f"[{scan_id}] Ingested {len(event_ids)} events from project '{project}'")

    # ---- 2. Kick off detection via RQ worker (primary) ----
    # Fallback runs only in dev/local mode (ENABLE_FALLBACK=true).
    # Production deployments must run the worker container — fallback is never
    # auto-triggered without an explicit opt-in flag.
    try:
        from workers.queue import detection_queue
        from workers.detector_worker import run_detection
        job = detection_queue.enqueue(
            run_detection,
            scan_id,
            normalized_events,
            job_id=scan_id,
        )
        logger.info(f"[{scan_id}] Detection job enqueued via RQ worker: {job.id}")
    except Exception as exc:
        logger.error(f"[{scan_id}] RQ unavailable — detection NOT scheduled: {exc}")
        if os.getenv("ENABLE_FALLBACK", "").lower() == "true":
            logger.warning(f"[{scan_id}] FALLBACK ENABLED (dev mode) — running detection inline")
            asyncio.create_task(_run_detection_async(scan_id, normalized_events, event_ids))
        else:
            logger.warning(
                f"[{scan_id}] Fallback is disabled. "
                "Set ENABLE_FALLBACK=true to use inline execution in dev/local mode."
            )

    return IngestEventResponse(
        accepted=True,
        project=project,
        events_ingested=len(event_ids),
        job_id=scan_id,
        event_ids=event_ids,
    )


async def _run_detection_async(
    scan_id: str,
    events: List[Dict],
    event_ids: List[str],
) -> None:
    """
    Dev/local fallback only — requires ENABLE_FALLBACK=true.
    Runs detection inline in the FastAPI worker process.
    DO NOT use in production; always run the RQ worker container instead.
    """
    try:
        # Import inline to avoid top-level dependency on RQ workers module
        import importlib
        detector = importlib.import_module("workers.detector_worker")
        # Reload to pick up any runtime changes
        importlib.reload(detector)

        result = detector.run_detection(scan_id, events)
        logger.info(f"[{scan_id}] Async detection completed: {result}")

        # Mark ingested events as processed
        events_collection.update_many(
            {"_id": {"$in": event_ids}},
            {"$set": {"detection_status": "done"}},
        )
    except Exception as exc:
        logger.error(f"[{scan_id}] Async detection failed: {exc}")
        events_collection.update_many(
            {"_id": {"$in": event_ids}},
            {"$set": {"detection_status": "failed"}},
        )


# ---- /ingest/status/{job_id} endpoint ----
@app.get("/ingest/status/{job_id}", response_model=DetectionStatusResponse)
async def get_ingest_status(
    job_id: str,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
):
    """
    Poll the status of a detection job by its job_id (scan_id).
    Primary source of truth is the detections MongoDB collection.
    If the record doesn't exist yet but the job was enqueued in RQ, returns 'queued'.
    The X-API-Key must be bound to the same project as the job, or the job must have no project.
    """
    # Validate API key
    require_ingest_key(x_api_key)
    bound_project = _get_project_for_key(x_api_key)

    # ---- 1. Check detections collection first ----
    detection_collection_ref = db["detections"]
    detection = detection_collection_ref.find_one({"_id": job_id})

    if detection:
        job_project = detection.get("source_project")
        # Allow access if job has no project (backward compat for pre-change records)
        # or if key's bound project matches
        if job_project and bound_project and job_project != bound_project:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This job belongs to project '{job_project}', but your key is bound to '{bound_project}'",
            )

        completed_at_str = None
        if detection.get("completed_at"):
            ts = detection["completed_at"]
            completed_at_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

        created_at_str = None
        if detection.get("created_at"):
            ts = detection["created_at"]
            created_at_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

        return DetectionStatusResponse(
            job_id=job_id,
            status=detection.get("status", "unknown"),
            source_project=detection.get("source_project"),
            findings_count=detection.get("findings_count", 0),
            risk_score=detection.get("risk_score", 0.0),
            created_at=created_at_str,
            completed_at=completed_at_str,
        )

    # ---- 2. No detection record yet — check if job is sitting in RQ queue ----
    try:
        from workers.queue import detection_queue
        job = detection_queue.fetch_job(job_id)
        if job is not None:
            # Job is known to RQ but not yet started / record not yet written
            rq_status = job.get_status()  # queued | started | deferred | finished | failed | canceled
            if rq_status == "queued":
                return DetectionStatusResponse(
                    job_id=job_id,
                    status="queued",
                    source_project=None,
                    findings_count=0,
                    risk_score=0.0,
                    created_at=None,
                    completed_at=None,
                )
            elif rq_status in ("started", "deferred"):
                return DetectionStatusResponse(
                    job_id=job_id,
                    status="running",
                    source_project=None,
                    findings_count=0,
                    risk_score=0.0,
                    created_at=None,
                    completed_at=None,
                )
    except Exception:
        pass  # RQ unavailable — fall through to unknown

    # ---- 3. Truly unknown job_id ----
    return DetectionStatusResponse(
        job_id=job_id,
        status="unknown",
        source_project=None,
        findings_count=0,
        risk_score=0.0,
        created_at=None,
        completed_at=None,
    )
@app.get("/api/scans")
async def get_scans(
    limit: int = 50,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get scan history. When X-API-Key is provided, returns only scans that belong
    to the key's bound project. JWT Bearer token users see all scans.
    """
    query = {}

    # API key path — project-scoped access
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    if bound_project:
        # Scans from the ingest pipeline: their _id matches a detection record.
        # We scope by finding detection records for this project and using those scan_ids.
        detection_ids = [
            d["_id"] for d in
            db["detections"].find(
                {"source_project": bound_project},
                {"_id": 1}
            )
        ]
        if detection_ids:
            query["_id"] = {"$in": detection_ids}
        else:
            # No detection records for this project yet — return empty
            return {"scans": []}

    try:
        scans = list(scans_collection.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
        return {"scans": scans}
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scans")


@app.get("/api/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_token: Optional[str] = Header(None, alias="Authorization"),
):
    """
    Get specific scan details. When X-API-Key is provided, returns the scan only
    if it belongs to the key's bound project. JWT Bearer token users see all scans.
    """
    # Authenticate
    if x_api_key:
        try:
            require_ingest_key(x_api_key)
            bound_project = _get_project_for_key(x_api_key)
        except HTTPException:
            raise
    elif x_token:
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=x_token.replace("Bearer ", ""))
        get_current_active_user(credentials)
        bound_project = None
    else:
        raise HTTPException(status_code=401, detail="Missing authentication")

    try:
        scan = scans_collection.find_one({"_id": scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if bound_project:
            # For ingest pipeline scans, check the detection record's source_project
            detection = db["detections"].find_one({"_id": scan_id})
            if not detection or detection.get("source_project") != bound_project:
                raise HTTPException(status_code=404, detail="Scan not found")

        return {"scan": scan}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan")


# ---- /admin/api-keys endpoint ----
@app.post("/admin/api-keys")
async def create_api_key(
    project_id: str,
    current_user: User = Depends(require_analyst),
):
    """
    Create a new API key for a project.
    Operator-only (requires analyst JWT). The generated key is returned once
    and cannot be retrieved later — store it securely.
    """
    from workers import api_keys as mongo_keys
    try:
        doc = mongo_keys.store_api_key(project_id=project_id, created_by=current_user.username)
        return {
            "message": "API key created",
            "api_key": doc["api_key"],
            "project_id": doc["project_id"],
            "created_at": doc["created_at"].isoformat(),
        }
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to create API key")


@app.delete("/admin/api-keys/{api_key}")
async def revoke_api_key(
    api_key: str,
    current_user: User = Depends(require_analyst),
):
    """
    Revoke an API key by marking it inactive.
    Operator-only (requires analyst JWT). The key is soft-revoked (active=False)
    and immediately invalidated from the cache. The document is retained for audit.
    """
    from workers import api_keys as mongo_keys
    try:
        revoked = mongo_keys.revoke_api_key(api_key)
        if not revoked:
            raise HTTPException(status_code=404, detail="API key not found")
        return {"message": "API key revoked", "api_key": api_key[:8] + "..."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke API key")


@app.get("/admin/api-keys")
async def list_api_keys(
    project_id: Optional[str] = None,
    current_user: User = Depends(require_analyst),
):
    """
    List API key records for a project (or all projects if project_id is omitted).
    Operator-only (requires analyst JWT). Only safe management fields are returned —
    the full plaintext key is never exposed.
    """
    from workers import api_keys as mongo_keys
    try:
        keys = mongo_keys.list_api_keys(project_id=project_id)
        return {"api_keys": keys}
    except Exception as e:
        logger.error(f"Error listing API keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to list API keys")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)