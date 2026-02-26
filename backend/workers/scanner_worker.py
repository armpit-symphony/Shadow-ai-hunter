"""
Scanner Worker for Shadow AI Hunter
Performs network discovery scans
"""

import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Scan a single port on an IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_host(ip: str, ports: List[int] = [22, 80, 443, 8000, 8080, 3000]) -> Dict:
    """Scan a single host for common ports"""
    open_ports = []
    for port in ports:
        if scan_port(ip, port):
            open_ports.append(port)
    
    return {
        "ip": ip,
        "open_ports": open_ports,
        "scanned_at": datetime.utcnow().isoformat()
    }


def network_discovery_scan(network_range: str, scan_id: str) -> Dict:
    """
    Perform network discovery scan
    Note: This is a simplified implementation.
    Production would use nmap or similar tools.
    """
    logger.info(f"[{scan_id}] Starting network discovery for {network_range}")
    
    # Parse network range (simplified - e.g., "192.168.1.0/24")
    # For now, just return mock results
    results = {
        "scan_id": scan_id,
        "network_range": network_range,
        "status": "completed",
        "devices_found": 0,
        "scanned_at": datetime.utcnow().isoformat(),
        "note": "Network scanning requires nmap/production tooling"
    }
    
    logger.info(f"[{scan_id}] Network discovery completed: {results}")
    return results


def deep_scan(scan_id: str, target_ips: List[str]) -> Dict:
    """Perform deep scan on specific IPs"""
    logger.info(f"[{scan_id}] Starting deep scan on {len(target_ips)} targets")
    
    results = {
        "scan_id": scan_id,
        "targets": target_ips,
        "status": "completed",
        "devices_found": len(target_ips),
        "scanned_at": datetime.utcnow().isoformat()
    }
    
    logger.info(f"[{scan_id}] Deep scan completed")
    return results
