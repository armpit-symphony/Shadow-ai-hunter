from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
from datetime import datetime, timedelta
import asyncio
import json
import logging
from contextlib import asynccontextmanager

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

# Security
security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Shadow AI Hunter Backend...")
    # Initialize collections with indexes
    try:
        scans_collection.create_index("timestamp")
        devices_collection.create_index("ip_address")
        alerts_collection.create_index("created_at")
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
async def get_dashboard_stats(current_user: User = Depends(require_viewer)):
    """Get overall dashboard statistics"""
    try:
        total_devices = devices_collection.count_documents({})
        high_risk_devices = devices_collection.count_documents({"ai_risk_score": {"$gte": 0.7}})
        active_threats = alerts_collection.count_documents({"resolved": False, "severity": {"$in": ["high", "critical"]}})
        total_scans = scans_collection.count_documents({})
        ai_services_blocked = policies_collection.count_documents({"rule_type": "block", "enabled": True})
        
        # Calculate compliance score based on policies and threats
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
async def get_devices(current_user: User = Depends(require_viewer)):
    """Get all detected devices"""
    try:
        devices = list(devices_collection.find({}, {"_id": 0}).sort("ai_risk_score", -1))
        return {"devices": devices}
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to get devices")

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, current_user: User = Depends(require_viewer)):
    """Get recent alerts"""
    try:
        alerts = list(alerts_collection.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get alerts")

@app.get("/api/policies")
async def get_policies(current_user: User = Depends(require_viewer)):
    """Get all policy rules"""
    try:
        policies = list(policies_collection.find({}, {"_id": 0}).sort("created_at", -1))
        return {"policies": policies}
    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        raise HTTPException(status_code=500, detail="Failed to get policies")

@app.post("/api/policies")
async def create_policy(policy: PolicyRule, current_user: User = Depends(require_analyst)):
    """Create a new policy rule"""
    try:
        policy.created_at = datetime.utcnow()
        result = policies_collection.insert_one(policy.dict())
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
        scan_data = {
            "network_range": scan_request.network_range,
            "scan_type": scan_request.scan_type,
            "deep_scan": scan_request.deep_scan,
            "status": "running",
            "timestamp": datetime.utcnow(),
            "devices_found": 0,
            "ai_services_detected": 0
        }
        result = scans_collection.insert_one(scan_data)
        scan_id = str(result.inserted_id)
        
        # Start background scan (simplified for now)
        asyncio.create_task(perform_network_scan(scan_id, scan_request))
        
        return {"message": "Scan initiated", "scan_id": scan_id}
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)