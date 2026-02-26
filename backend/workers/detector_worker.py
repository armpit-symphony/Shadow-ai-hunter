"""
Detection Worker for Shadow AI Hunter
Runs signature and heuristic detection on normalized events
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import json

logger = logging.getLogger(__name__)

# Known AI service signatures
AI_SERVICES = {
    "openai.com": {"name": "OpenAI", "category": "llm", "severity": "high"},
    "api.openai.com": {"name": "OpenAI API", "category": "llm", "severity": "high"},
    "chat.openai.com": {"name": "ChatGPT", "category": "llm", "severity": "high"},
    "anthropic.com": {"name": "Anthropic/Claude", "category": "llm", "severity": "high"},
    "api.anthropic.com": {"name": "Anthropic API", "category": "llm", "severity": "high"},
    "claude.ai": {"name": "Claude AI", "category": "llm", "severity": "high"},
    "midjourney.com": {"name": "Midjourney", "category": "image_gen", "severity": "medium"},
    "stability.ai": {"name": "Stability AI", "category": "image_gen", "severity": "medium"},
    "replicate.com": {"name": "Replicate", "category": "ml_inference", "severity": "medium"},
    "huggingface.co": {"name": "Hugging Face", "category": "ml_inference", "severity": "medium"},
    "cohere.ai": {"name": "Cohere", "category": "llm", "severity": "medium"},
    "ai21.com": {"name": "AI21 Labs", "category": "llm", "severity": "medium"},
    "writesonic.com": {"name": "Writesonic", "category": "content", "severity": "low"},
    "jasper.ai": {"name": "Jasper", "category": "content", "severity": "low"},
    "copy.ai": {"name": "Copy.ai", "category": "content", "severity": "low"},
}

# Allowlist (approved services)
ALLOWLIST = [
    "company-internal-ai.company.com",
    "ai.company-internal.local",
]


def load_allowlist() -> List[str]:
    """Load allowlist from config or database"""
    # TODO: Load from database
    return ALLOWLIST


def detect_ai_services(event: Dict) -> List[Dict]:
    """Detect AI services in network event"""
    findings = []
    
    # Check destination domain
    dest_domain = event.get("dest_domain", "").lower()
    if dest_domain in AI_SERVICES:
        service = AI_SERVICES[dest_domain]
        findings.append({
            "type": "ai_service_match",
            "indicator": dest_domain,
            "service": service["name"],
            "category": service["category"],
            "severity": service["severity"],
            "confidence": 0.95
        })
    
    # Check TLS SNI
    tls_sni = event.get("tls_sni", "").lower()
    if tls_sni and tls_sni in AI_SERVICES:
        service = AI_SERVICES[tls_sni]
        findings.append({
            "type": "ai_service_sni_match",
            "indicator": tls_sni,
            "service": service["name"],
            "category": service["category"],
            "severity": service["severity"],
            "confidence": 0.95
        })
    
    return findings


def heuristic_detection(event: Dict, baseline: Optional[Dict] = None) -> List[Dict]:
    """Run heuristic detection rules"""
    findings = []
    
    # Heuristic 1: High volume upload to AI endpoint
    if event.get("bytes_out", 0) > 1000000:  # > 1MB
        if any(AI_SERVICES.get(event.get("dest_domain", "").lower())):
            findings.append({
                "type": "high_volume_upload",
                "indicator": f"{event.get('dest_domain')} ({event.get('bytes_out')} bytes)",
                "severity": "high",
                "confidence": 0.8
            })
    
    # Heuristic 2: Unmanaged device accessing AI
    device_id = event.get("device_id", "")
    # TODO: Check against approved device list
    
    # Heuristic 3: New AI destination (not in baseline)
    if baseline and event.get("dest_domain") not in baseline.get("known_ai_domains", []):
        findings.append({
            "type": "new_ai_destination",
            "indicator": event.get("dest_domain"),
            "severity": "medium",
            "confidence": 0.6
        })
    
    return findings


def compute_risk_score(findings: List[Dict], asset_criticality: float = 0.5) -> float:
    """Compute risk score from findings"""
    if not findings:
        return 0.0
    
    severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    
    max_severity = max(findings, key=lambda f: severity_weights.get(f.get("severity", "low"), 0.3))
    severity = severity_weights.get(max_severity.get("severity", "low"), 0.3)
    
    confidence = max(f.get("confidence", 0.5) for f in findings)
    
    # Risk = severity × confidence × asset_criticality
    return min(1.0, severity * confidence * asset_criticality)


def create_evidence_bundle(events: List[Dict], findings: List[Dict]) -> Dict:
    """Create evidence bundle for an alert"""
    evidence = {
        "created_at": datetime.utcnow().isoformat(),
        "event_count": len(events),
        "finding_count": len(findings),
        "event_ids": [e.get("id", "unknown") for e in events],
        "findings": findings,
        "evidence_hash": hashlib.sha256(
            json.dumps(events, sort_keys=True).encode()
        ).hexdigest()
    }
    return evidence


def run_detection(scan_id: str, events: List[Dict]) -> Dict:
    """Main detection worker function"""
    logger.info(f"[{scan_id}] Running detection on {len(events)} events")
    
    all_findings = []
    
    for event in events:
        # Signature-based detection
        ai_findings = detect_ai_services(event)
        all_findings.extend(ai_findings)
        
        # Heuristic detection
        heuristic_findings = heuristic_detection(event)
        all_findings.extend(heuristic_findings)
    
    # Compute risk score
    risk_score = compute_risk_score(all_findings)
    
    # Create evidence bundle
    evidence = create_evidence_bundle(events, all_findings)
    
    result = {
        "scan_id": scan_id,
        "status": "completed",
        "events_processed": len(events),
        "findings_count": len(all_findings),
        "risk_score": risk_score,
        "evidence": evidence,
        "completed_at": datetime.utcnow().isoformat()
    }
    
    logger.info(f"[{scan_id}] Detection completed: {len(all_findings)} findings, risk: {risk_score}")
    return result
