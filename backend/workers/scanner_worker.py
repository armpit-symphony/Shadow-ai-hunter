"""
Scanner Worker for Shadow AI Hunter

Performs network host discovery and fingerprints locally-running AI services.

Detection strategy:
  - Network scanning alone CANNOT see what external AI APIs a device calls.
    That requires DNS/proxy telemetry (see detector_worker + telemetry_worker).
  - What network scanning CAN detect:
      * Locally running AI services (Ollama, LocalAI, Gradio, Jupyter, etc.)
      * AI infrastructure (TensorFlow Serving, Triton, Ray, MLflow, etc.)
      * Development environments that indicate ML workloads
  - If nmap is available: uses PortScanner for fast, reliable results.
  - Fallback: plain TCP connect scan (slower, no service fingerprinting).

Requires nmap to be installed on the host:  apt-get install nmap
"""

import ipaddress
import json
import logging
import os
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable
import redis

logger = logging.getLogger(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# nmap availability check
# ---------------------------------------------------------------------------
try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning(
        "python-nmap not importable. Install nmap + python-nmap for full scanning. "
        "Falling back to TCP connect scan."
    )

# ---------------------------------------------------------------------------
# Port → AI service signatures
# Ports that indicate a locally running AI/ML service
# ---------------------------------------------------------------------------

LOCAL_AI_PORTS: Dict[int, Dict] = {
    # Local LLM servers
    11434: {"service": "Ollama", "category": "local_llm", "severity": "high"},
    8080: {"service": "LocalAI / Generic AI API", "category": "local_llm", "severity": "medium"},
    1234: {"service": "LM Studio", "category": "local_llm", "severity": "high"},
    8082: {"service": "KoboldAI", "category": "local_llm", "severity": "high"},
    5000: {"service": "MLflow / Flask AI (port 5000)", "category": "ml_dev", "severity": "medium"},
    5001: {"service": "Triton Inference Server HTTP", "category": "ml_inference", "severity": "high"},
    8001: {"service": "Triton Inference Server HTTP v2", "category": "ml_inference", "severity": "high"},
    # ML inference / serving
    8500: {"service": "TensorFlow Serving gRPC", "category": "ml_inference", "severity": "high"},
    8501: {"service": "TensorFlow Serving REST", "category": "ml_inference", "severity": "high"},
    8600: {"service": "TorchServe Management", "category": "ml_inference", "severity": "medium"},
    8070: {"service": "TorchServe Inference", "category": "ml_inference", "severity": "high"},
    # ML development UIs
    7860: {"service": "Gradio UI", "category": "ml_ui", "severity": "medium"},
    8888: {"service": "Jupyter Notebook", "category": "ml_dev", "severity": "medium"},
    8889: {"service": "Jupyter Lab", "category": "ml_dev", "severity": "medium"},
    6006: {"service": "TensorBoard", "category": "ml_dev", "severity": "low"},
    # Distributed ML / infra
    8265: {"service": "Ray Dashboard", "category": "ml_infra", "severity": "medium"},
    6379: None,  # Redis - too common, skip
    8786: {"service": "Dask Scheduler", "category": "ml_infra", "severity": "low"},
    8787: {"service": "Dask Dashboard", "category": "ml_infra", "severity": "low"},
    # Generic AI web UIs (common ports used by AI chat UIs)
    3001: {"service": "Open WebUI / Chat UI (port 3001)", "category": "local_llm", "severity": "medium"},
    3002: {"service": "AI Chat UI (port 3002)", "category": "local_llm", "severity": "medium"},
    9000: {"service": "Generic AI Service (port 9000)", "category": "ml_inference", "severity": "low"},
    # Cloud-style inference within org network
    4000: {"service": "Text-generation-webui API", "category": "local_llm", "severity": "high"},
    5555: {"service": "Oobabooga API (port 5555)", "category": "local_llm", "severity": "high"},
}

# Remove None entries (excluded common ports)
LOCAL_AI_PORTS = {k: v for k, v in LOCAL_AI_PORTS.items() if v is not None}

# ---------------------------------------------------------------------------
# HTTP banner patterns that confirm AI software
# ---------------------------------------------------------------------------

AI_BANNER_PATTERNS: List[str] = [
    "ollama",
    "localai",
    "gradio",
    "jupyter",
    "tensorflow",
    "pytorch",
    "hugging",
    "mlflow",
    "ray serve",
    "triton",
    "lm studio",
    "llamafile",
    "text-generation",
    "kobold",
    "oobabooga",
    "stable diffusion",
    "openai",
]

SCAN_MAX_HOSTS = int(os.getenv("SCAN_MAX_HOSTS", "254"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_db():
    """Get a direct MongoDB connection for use inside worker processes."""
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
    from pymongo import MongoClient

    client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
    return client, client.shadow_ai_hunter


def _emit_ws_event(db, payload: Dict) -> None:
    try:
        db.ws_events.insert_one({**payload, "created_at": now_utc()})
    except Exception:
        pass
    try:
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            r = redis.Redis.from_url(redis_url, decode_responses=True)
            r.publish("ws_events", json.dumps(payload, default=str))
    except Exception:
        pass


def probe_http_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Send a minimal HTTP HEAD request and read the first 1 KB of the response.
    Returns the lowercased response text, or None on failure.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            return s.recv(1024).decode("utf-8", errors="ignore").lower()
    except Exception:
        return None


def identify_ai_banner(banner: str) -> Optional[str]:
    """Return the first matching AI pattern found in a banner, or None."""
    if not banner:
        return None
    for pat in AI_BANNER_PATTERNS:
        if pat in banner:
            return pat
    return None


def _guess_device_type(open_ports: List[int]) -> str:
    ml_server_ports = {8500, 8501, 5001, 8001, 8070, 8600}
    local_llm_ports = {11434, 1234, 8082, 4000, 5555}
    dev_ports = {8888, 8889, 6006, 7860}

    if open_ports and set(open_ports) & ml_server_ports:
        return "ml-server"
    if open_ports and set(open_ports) & local_llm_ports:
        return "local-llm-host"
    if open_ports and set(open_ports) & dev_ports:
        return "developer-workstation"
    if 22 in open_ports:
        return "server"
    return "unknown"


def _calculate_scan_risk(evidence: List[Dict]) -> float:
    """Simple risk score from scan evidence fragments."""
    if not evidence:
        return 0.0
    severity_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    max_sev = max(severity_map.get(e.get("severity", "low"), 0.2) for e in evidence)
    count_bonus = min(0.15, len(evidence) * 0.03)
    return min(1.0, max_sev + count_bonus)


# ---------------------------------------------------------------------------
# nmap scanning
# ---------------------------------------------------------------------------

def _nmap_scan(
    network_range: str,
    scan_id: str,
    progress_cb: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """Use python-nmap for host discovery + targeted port scanning."""
    nm = nmap.PortScanner()
    ai_port_list = ",".join(str(p) for p in sorted(LOCAL_AI_PORTS.keys()))
    common_ports = "22,80,443,8080,3000,3001"
    all_ports = f"{ai_port_list},{common_ports}"

    logger.info(f"[{scan_id}] nmap host discovery on {network_range}")
    nm.scan(hosts=network_range, arguments="-sn --max-retries 1 --host-timeout 5s")
    live_hosts = [h for h in nm.all_hosts() if nm[h].state() == "up"]
    logger.info(f"[{scan_id}] {len(live_hosts)} live hosts found")
    if progress_cb:
        progress_cb({
            "type": "scan_hosts_discovered",
            "scan_id": scan_id,
            "hosts_total": len(live_hosts),
        })

    devices: List[Dict] = []
    scanned = 0
    for ip in live_hosts:
        try:
            nm.scan(
                hosts=ip,
                ports=all_ports,
                arguments="-sT -T4 --open --max-retries 1 --host-timeout 30s",
            )
            host = nm[ip]
            hostname = host.hostnames()[0].get("name", "") if host.hostnames() else ""

            open_ports: List[int] = []
            evidence: List[Dict] = []
            ai_services: List[str] = []

            for proto in host.all_protocols():
                for port, info in host[proto].items():
                    if info["state"] != "open":
                        continue
                    open_ports.append(port)
                    sig = LOCAL_AI_PORTS.get(port)
                    if sig:
                        ai_services.append(sig["service"])
                        evidence.append({
                            "type": "open_ai_port",
                            "port": port,
                            "service": sig["service"],
                            "category": sig["category"],
                            "severity": sig["severity"],
                            "nmap_name": info.get("name", ""),
                            "nmap_product": info.get("product", ""),
                            "nmap_version": info.get("version", ""),
                        })

                    # Banner grab for extra confirmation
                    banner = probe_http_banner(ip, port)
                    matched = identify_ai_banner(banner) if banner else None
                    if matched and not sig:
                        ai_services.append(f"AI Service ({matched})")
                        evidence.append({
                            "type": "ai_http_banner",
                            "port": port,
                            "pattern": matched,
                            "severity": "high",
                        })

            if open_ports:
                devices.append({
                    "ip_address": ip,
                    "hostname": hostname,
                    "device_type": _guess_device_type(open_ports),
                    "open_ports": open_ports,
                    "ai_services_detected": list(set(ai_services)),
                    "ai_risk_score": _calculate_scan_risk(evidence),
                    "evidence": evidence,
                    "scan_id": scan_id,
                    "last_seen": now_utc(),
                    "status": "active",
                })
            scanned += 1
            if progress_cb:
                progress_cb({
                    "type": "scan_host_scanned",
                    "scan_id": scan_id,
                    "host": ip,
                    "hosts_scanned": scanned,
                    "hosts_total": len(live_hosts),
                })
        except Exception as e:
            logger.warning(f"[{scan_id}] Error scanning {ip}: {e}")

    return devices


# ---------------------------------------------------------------------------
# TCP connect fallback scanning
# ---------------------------------------------------------------------------

def _socket_scan(
    network_range: str,
    scan_id: str,
    progress_cb: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """TCP connect scan fallback when nmap is not available."""
    try:
        network = ipaddress.ip_network(network_range, strict=False)
    except ValueError as e:
        logger.error(f"[{scan_id}] Invalid network range '{network_range}': {e}")
        return []

    hosts = list(network.hosts())[:SCAN_MAX_HOSTS]
    logger.info(f"[{scan_id}] TCP connect fallback on {len(hosts)} hosts")

    devices: List[Dict] = []
    scanned = 0
    total = len(hosts)
    if progress_cb:
        progress_cb({
            "type": "scan_hosts_discovered",
            "scan_id": scan_id,
            "hosts_total": total,
        })
    for ip_obj in hosts:
        ip = str(ip_obj)
        open_ports: List[int] = []
        evidence: List[Dict] = []
        ai_services: List[str] = []

        for port, sig in LOCAL_AI_PORTS.items():
            try:
                with socket.create_connection((ip, port), timeout=0.5):
                    open_ports.append(port)
                    ai_services.append(sig["service"])
                    evidence.append({
                        "type": "open_ai_port",
                        "port": port,
                        "service": sig["service"],
                        "category": sig["category"],
                        "severity": sig["severity"],
                    })
                    # Banner grab
                    banner = probe_http_banner(ip, port, timeout=1.0)
                    matched = identify_ai_banner(banner) if banner else None
                    if matched:
                        evidence[-1]["banner_confirmed"] = True
                        evidence[-1]["banner_pattern"] = matched
            except (OSError, ConnectionRefusedError):
                pass
            except Exception:
                pass

        if open_ports:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""

            devices.append({
                "ip_address": ip,
                "hostname": hostname,
                "device_type": _guess_device_type(open_ports),
                "open_ports": open_ports,
                "ai_services_detected": list(set(ai_services)),
                "ai_risk_score": _calculate_scan_risk(evidence),
                "evidence": evidence,
                "scan_id": scan_id,
                "last_seen": now_utc(),
                "status": "active",
            })
        scanned += 1
        if progress_cb:
            progress_cb({
                "type": "scan_host_scanned",
                "scan_id": scan_id,
                "host": ip,
                "hosts_scanned": scanned,
                "hosts_total": total,
            })

    return devices


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def network_discovery_scan(network_range: str, scan_id: str) -> Dict:
    """
    Primary scanner worker function.  Called by RQ or the async fallback.

    Steps:
      1. Update scan record to 'running'
      2. Discover hosts and fingerprint AI services
      3. Persist device records and generate alerts
      4. Update scan record to 'completed'
    """
    logger.info(f"[{scan_id}] Starting network discovery for {network_range}")

    # Connect to MongoDB (workers run in separate processes)
    _client = None
    _db = None
    try:
        _client, _db = get_db()
        _db.scans.update_one(
            {"_id": scan_id, "status": {"$in": ["queued", "running"]}},
            {"$set": {"status": "running", "started_at": now_utc()}},
        )
        _emit_ws_event(_db, {
            "type": "scan_started",
            "scan_id": scan_id,
            "network_range": network_range,
            "status": "running",
        })
    except Exception as e:
        logger.warning(f"[{scan_id}] Cannot connect to MongoDB at startup: {e}")

    # --- Perform the scan ---
    def _progress(payload: Dict) -> None:
        if _db is not None:
            _emit_ws_event(_db, {**payload, "network_range": network_range})

    try:
        if NMAP_AVAILABLE:
            devices = _nmap_scan(network_range, scan_id, progress_cb=_progress)
        else:
            devices = _socket_scan(network_range, scan_id, progress_cb=_progress)
    except Exception as e:
        logger.error(f"[{scan_id}] Scan execution failed: {e}")
        if _db is not None:
            _db.scans.update_one(
                {"_id": scan_id, "status": {"$in": ["queued", "running"]}},
                {"$set": {"status": "failed", "error": str(e)}},
            )
            _emit_ws_event(_db, {
                "type": "scan_failed",
                "scan_id": scan_id,
                "network_range": network_range,
                "status": "failed",
                "error": str(e),
            })
        if _client:
            _client.close()
        return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    # --- Persist results ---
    ai_service_count = 0
    alerts_created = 0
    processed_count = 0

    if _db is not None:
        for device in devices:
            try:
                # Convert datetime for MongoDB
                device_doc = {**device, "last_seen": now_utc()}
                _db.devices.replace_one(
                    {"ip_address": device["ip_address"]},
                    device_doc,
                    upsert=True,
                )
                ai_service_count += len(device["ai_services_detected"])

                if device["ai_risk_score"] >= 0.5:
                    alert = {
                        "title": (
                            f"AI Service Detected: {device['ip_address']} "
                            f"({', '.join(device['ai_services_detected'][:3])})"
                        ),
                        "description": (
                            f"Device {device['ip_address']} "
                            f"(hostname: {device.get('hostname') or 'unknown'}) "
                            f"has {len(device['ai_services_detected'])} AI service(s) running: "
                            f"{', '.join(device['ai_services_detected'])}"
                        ),
                        "severity": (
                            "high" if device["ai_risk_score"] >= 0.8 else "medium"
                        ),
                        "device_ip": device["ip_address"],
                        "alert_type": "ai_service_discovered",
                        "evidence": device.get("evidence", []),
                        "scan_id": scan_id,
                        "created_at": now_utc(),
                        "resolved": False,
                    }
                    _db.alerts.insert_one(alert)
                    alerts_created += 1

                processed_count += 1
                _db.scans.update_one(
                    {"_id": scan_id},
                    {"$set": {
                        "devices_found": processed_count,
                        "ai_services_detected": ai_service_count,
                        "alerts_created": alerts_created,
                    }},
                )
                _emit_ws_event(_db, {
                    "type": "scan_progress",
                    "scan_id": scan_id,
                    "device_ip": device["ip_address"],
                    "devices_found": processed_count,
                    "ai_services_detected": ai_service_count,
                    "alerts_created": alerts_created,
                    "status": "running",
                })
            except Exception as e:
                logger.error(
                    f"[{scan_id}] Error persisting device {device['ip_address']}: {e}"
                )

        _db.scans.update_one(
            {"_id": scan_id, "status": {"$in": ["running"]}},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": now_utc(),
                    "devices_found": len(devices),
                    "ai_services_detected": ai_service_count,
                    "alerts_created": alerts_created,
                    "nmap_used": NMAP_AVAILABLE,
                }
            },
        )
        _emit_ws_event(_db, {
            "type": "scan_completed",
            "scan_id": scan_id,
            "network_range": network_range,
            "devices_found": len(devices),
            "ai_services_detected": ai_service_count,
            "alerts_created": alerts_created,
            "status": "completed",
        })

    if _client:
        _client.close()

    result = {
        "scan_id": scan_id,
        "network_range": network_range,
        "status": "completed",
        "devices_found": len(devices),
        "ai_services_detected": ai_service_count,
        "alerts_created": alerts_created,
        "nmap_used": NMAP_AVAILABLE,
        "completed_at": now_utc().isoformat(),
    }

    logger.info(
        f"[{scan_id}] Scan completed: {len(devices)} devices, "
        f"{ai_service_count} AI services, {alerts_created} alerts"
    )
    return result


def deep_scan(scan_id: str, target_ips: List[str]) -> Dict:
    """Perform a targeted deep scan on a list of specific IP addresses."""
    logger.info(f"[{scan_id}] Deep scan on {len(target_ips)} targets")
    all_devices = 0
    for ip in target_ips:
        result = network_discovery_scan(ip, scan_id)
        all_devices += result.get("devices_found", 0)
    return {
        "scan_id": scan_id,
        "targets": target_ips,
        "status": "completed",
        "devices_found": all_devices,
        "completed_at": now_utc().isoformat(),
    }
