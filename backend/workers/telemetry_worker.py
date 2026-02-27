"""
Telemetry Ingestion Worker for Shadow AI Hunter
Parses and normalizes DNS and Proxy/HTTP logs
"""

import logging
import re
import os
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_dns_log(line: str) -> Optional[Dict]:
    """
    Parse DNS log line into normalized event
    Supports common formats: bind, unbound, dnsmasq
    """
    try:
        # Example dnsmasq format:
        # Feb 26 10:00:00 hostname dnsmasq[123]: query[A] example.com from 192.168.1.100
        # Feb 26 10:00:00 hostname dnsmasq[123]: reply example.com is 1.2.3.4
        
        # Query pattern
        query_match = re.search(r'query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)', line)
        if query_match:
            return {
                "type": "dns_query",
                "query_type": query_match.group(1),
                "domain": query_match.group(2),
                "source_ip": query_match.group(3),
                "timestamp": extract_timestamp(line),
                "raw": line
            }
        
        # Reply pattern
        reply_match = re.search(r'reply\s+(\S+)\s+is\s+(\S+)', line)
        if reply_match:
            return {
                "type": "dns_reply",
                "domain": reply_match.group(1),
                "resolved_ip": reply_match.group(2),
                "timestamp": extract_timestamp(line),
                "raw": line
            }
        
        return None
    except Exception as e:
        logger.warning(f"Failed to parse DNS log: {e}")
        return None


def parse_proxy_log(line: str) -> Optional[Dict]:
    """
    Parse proxy/HTTP access log into normalized event
    Supports common formats: Squid, nginx, Apache
    """
    try:
        # Common proxy format (Squid):
        # 192.168.1.100 - - [26/Feb/2026:10:00:00 +0000] "GET https://api.openai.com/v1/chat/completions HTTP/1.1" 200 1234 "Mozilla/5.0" "application/json"
        
        # Extract IP
        ip_match = re.match(r'^(\S+)', line)
        if not ip_match:
            return None
        
        # Extract timestamp
        ts_match = re.search(r'\[([^\]]+)\]', line)
        
        # Extract request
        request_match = re.search(r'"(\w+)\s+(\S+)\s+(\S+)"', line)
        
        # Extract response code and size
        response_match = re.search(r'" (\d+) (\d+)', line)
        
        # Extract User-Agent
        ua_match = re.search(r'"([^"]+)"\s+"([^"]+)"', line)
        
        if request_match:
            url = request_match.group(2)
            return {
                "type": "http_request",
                "source_ip": ip_match.group(1),
                "method": request_match.group(1),
                "url": url,
                "protocol": request_match.group(3),
                "status_code": int(response_match.group(1)) if response_match else None,
                "bytes_out": int(response_match.group(2)) if response_match else 0,
                "user_agent": ua_match.group(2) if ua_match else None,
        "timestamp": ts_match.group(1) if ts_match else now_utc().isoformat(),
                "dest_domain": extract_domain(url),
                "raw": line
            }
        
        return None
    except Exception as e:
        logger.warning(f"Failed to parse proxy log: {e}")
        return None


def extract_timestamp(line: str) -> str:
    """Extract timestamp from log line"""
    # Try common formats
    patterns = [
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})',
        r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    
    return now_utc().isoformat()


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    # Remove protocol
    if '://' in url:
        url = url.split('://', 1)[1]
    # Remove path
    if '/' in url:
        url = url.split('/', 1)[0]
    # Remove port
    if ':' in url:
        url = url.split(':', 1)[0]
    return url


def infer_segment(ip: str) -> str:
    """
    Infer a network segment from source IP.
    Uses SEGMENT_MAP env like: "corp:10.0.0.0/24;lab:10.0.1.0/24".
    Falls back to /24 prefix of the IP.
    """
    if not ip:
        return "default"
    segment_map = os.getenv("SEGMENT_MAP", "")
    if segment_map:
        for entry in segment_map.split(";"):
            if not entry.strip():
                continue
            name, _, cidr = entry.partition(":")
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr.strip(), strict=False):
                    return name.strip() or "default"
            except Exception:
                continue
    try:
        parts = ip.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3]) + ".0/24"
    except Exception:
        pass
    return "default"


def normalize_event(event: Dict) -> Dict:
    """Normalize event to standard schema"""
    source_ip = event.get("source_ip", event.get("source", ""))
    normalized = {
        "id": event.get("id", ""),
        "ts": event.get("timestamp", now_utc().isoformat()),
        "source": source_ip,
        "segment": event.get("segment", infer_segment(source_ip)),
        "device_id": event.get("device_id", ""),
        "user": event.get("user", ""),
        "dest_domain": event.get("domain", event.get("dest_domain", "")),
        "dest_ip": event.get("resolved_ip", event.get("dest_ip", "")),
        "dest_port": event.get("dest_port", 0),
        "url_path": event.get("url_path", ""),
        "bytes_out": event.get("bytes_out", 0),
        "bytes_in": event.get("bytes_in", 0),
        "tls_sni": event.get("tls_sni", ""),
        "user_agent": event.get("user_agent", ""),
        "raw_ref": event.get("raw", ""),
        "event_type": event.get("type", "unknown")
    }
    return normalized


def process_log_file(file_path: str, log_type: str = "dns") -> List[Dict]:
    """Process a log file and return normalized events"""
    logger.info(f"Processing {log_type} log file: {file_path}")
    
    events = []
    parser = parse_dns_log if log_type == "dns" else parse_proxy_log
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                event = parser(line)
                if event:
                    normalized = normalize_event(event)
                    events.append(normalized)
    except FileNotFoundError:
        logger.error(f"Log file not found: {file_path}")
    except Exception as e:
        logger.error(f"Error processing log file: {e}")
    
    logger.info(f"Processed {len(events)} events from {file_path}")
    return events


def ingest_telemetry(scan_id: str, log_entries: List[Dict]) -> Dict:
    """Main telemetry ingestion worker"""
    logger.info(f"[{scan_id}] Ingesting {len(log_entries)} telemetry events")
    
    normalized_events = []
    
    for entry in log_entries:
        event_type = entry.get("type", "unknown")
        
        if event_type == "dns":
            parsed = parse_dns_log(entry.get("raw", ""))
        elif event_type in ["http", "proxy"]:
            parsed = parse_proxy_log(entry.get("raw", ""))
        else:
            parsed = entry
        
        if parsed:
            normalized = normalize_event(parsed)
            normalized_events.append(normalized)
    
    result = {
        "scan_id": scan_id,
        "status": "completed",
        "raw_entries": len(log_entries),
        "normalized_events": len(normalized_events),
        "completed_at": now_utc().isoformat()
    }
    
    logger.info(f"[{scan_id}] Telemetry ingestion completed: {len(normalized_events)} normalized events")
    return result
