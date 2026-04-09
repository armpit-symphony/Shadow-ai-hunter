"""
Enrichment Worker for Shadow AI Hunter

Cross-references scanner/detection findings with:
  - Policy rules in MongoDB (should this device/service be blocked?)
  - Asset criticality lookup (is this a high-value system?)
  - Deduplication (merge multiple scan results for the same IP)

Called after target_scanner or ai_usage_detector completes via the enrichment queue.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)

# Asset criticality tiers (can be overridden per-deployment via DB)
# Higher value = more sensitive system; affects final risk score weighting.
DEFAULT_CRITICALITY = 0.5
HIGH_CRITICALITY_DEVICE_TYPES = {"ml-server", "local-llm-host"}
MEDIUM_CRITICALITY_DEVICE_TYPES = {"developer-workstation", "server"}


def get_db():
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
    from pymongo import MongoClient

    client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
    return client, client.shadow_ai_hunter


def get_asset_criticality(device: Dict, db=None) -> float:
    """
    Return a 0–1 criticality score for a device.
    Checks the devices collection for an existing 'criticality' field,
    falls back to device_type heuristics.
    """
    if db is not None:
        doc = db.devices.find_one({"ip_address": device.get("ip_address", "")})
        if doc and "criticality" in doc:
            return float(doc["criticality"])

    device_type = device.get("device_type", "unknown")
    if device_type in HIGH_CRITICALITY_DEVICE_TYPES:
        return 0.9
    if device_type in MEDIUM_CRITICALITY_DEVICE_TYPES:
        return 0.6
    return DEFAULT_CRITICALITY


def evaluate_policies(device: Dict, ai_services: List[str], db=None) -> List[Dict]:
    """
    Check whether any enabled policy rules match the given device or its services.
    Returns a list of policy match dicts.
    """
    matches: List[Dict] = []
    if db is None:
        return matches

    try:
        policies = list(db.policies.find({"enabled": True}))
        for policy in policies:
            conditions = policy.get("conditions", {})
            matched = False

            # Condition: ai_services list overlap
            if "ai_services" in conditions:
                blocked_services = [s.lower() for s in conditions["ai_services"]]
                for svc in ai_services:
                    if svc.lower() in blocked_services:
                        matched = True
                        break

            # Condition: categories list
            if "categories" in conditions and not matched:
                # We'd need to look up categories from the signature DB
                # For now, treat as a match if any service is present
                if ai_services:
                    matched = True

            # Condition: risk score threshold
            if "ai_risk_score" in conditions and not matched:
                threshold = conditions["ai_risk_score"].get("$gte", 1.0)
                if device.get("ai_risk_score", 0) >= threshold:
                    matched = True

            if matched:
                matches.append({
                    "policy_id": str(policy.get("_id", "")),
                    "policy_name": policy.get("name", ""),
                    "rule_type": policy.get("rule_type", ""),
                    "actions": policy.get("actions", []),
                    "matched_at": now_utc().isoformat(),
                })
    except Exception as e:
        logger.warning(f"Policy evaluation error: {e}")

    return matches


def enrich_device(scan_id: str, device_ip: str) -> Dict:
    """
    Enrich a single device record after a scan.

    1. Load current device record from DB
    2. Compute asset criticality
    3. Evaluate active policies
    4. Adjust risk score with criticality weighting
    5. Create a policy-violation alert if a block/monitor policy matched
    6. Persist enriched record
    """
    logger.info(f"[{scan_id}] Enriching device {device_ip}")

    _client = None
    _db = None
    try:
        _client, _db = get_db()
    except Exception as e:
        logger.error(f"[{scan_id}] DB connection failed: {e}")
        return {"status": "failed", "error": str(e)}

    try:
        device = _db.devices.find_one({"ip_address": device_ip})
        if not device:
            logger.warning(f"[{scan_id}] Device {device_ip} not found for enrichment")
            return {"status": "skipped", "reason": "device not found"}

        ai_services = device.get("ai_services_detected", [])
        criticality = get_asset_criticality(device, _db)

        # Re-weight risk score with asset criticality
        base_score = device.get("ai_risk_score", 0.0)
        enriched_score = min(1.0, base_score * (0.6 + 0.4 * criticality))

        # Policy evaluation
        policy_matches = evaluate_policies(device, ai_services, _db)
        enforcement_actions: List[str] = []
        for match in policy_matches:
            enforcement_actions.extend(match.get("actions", []))

        # Deduplicate actions
        enforcement_actions = list(set(enforcement_actions))

        # Update device record
        _db.devices.update_one(
            {"ip_address": device_ip},
            {
                "$set": {
                    "ai_risk_score": enriched_score,
                    "asset_criticality": criticality,
                    "policy_matches": policy_matches,
                    "enforcement_actions": enforcement_actions,
                    "enriched_at": now_utc(),
                    "enrichment_scan_id": scan_id,
                }
            },
        )

        # Create policy-violation alert if needed
        if policy_matches and any(
            m.get("rule_type") in ("block", "monitor") for m in policy_matches
        ):
            alert = {
                "title": f"Policy Violation: {device_ip}",
                "description": (
                    f"Device {device_ip} matched {len(policy_matches)} active policy rule(s): "
                    f"{', '.join(m['policy_name'] for m in policy_matches)}. "
                    f"Recommended actions: {', '.join(enforcement_actions)}."
                ),
                "severity": "high" if enriched_score >= 0.7 else "medium",
                "device_ip": device_ip,
                "alert_type": "policy_violation",
                "policy_matches": policy_matches,
                "scan_id": scan_id,
                "created_at": now_utc(),
                "resolved": False,
            }
            _db.alerts.insert_one(alert)
            logger.info(f"[{scan_id}] Policy violation alert created for {device_ip}")

        result = {
            "status": "completed",
            "device_ip": device_ip,
            "enriched_risk_score": enriched_score,
            "asset_criticality": criticality,
            "policy_matches_count": len(policy_matches),
            "enforcement_actions": enforcement_actions,
        }
        logger.info(f"[{scan_id}] Enrichment done for {device_ip}: score={enriched_score:.2f}")
        return result

    except Exception as e:
        logger.error(f"[{scan_id}] Enrichment failed for {device_ip}: {e}")
        return {"status": "failed", "error": str(e)}
    finally:
        if _client:
            _client.close()


def enrich_scan(scan_id: str) -> Dict:
    """
    Enrich all devices discovered in a given scan.
    Called after network_discovery_scan completes.
    """
    logger.info(f"[{scan_id}] Starting bulk enrichment for scan")

    _client = None
    try:
        _client, _db = get_db()
        device_ips = [
            d["ip_address"]
            for d in _db.devices.find({"scan_id": scan_id}, {"ip_address": 1})
        ]
        _client.close()
    except Exception as e:
        logger.error(f"[{scan_id}] Cannot list devices for enrichment: {e}")
        return {"status": "failed", "error": str(e)}

    results = []
    for ip in device_ips:
        results.append(enrich_device(scan_id, ip))

    completed = sum(1 for r in results if r.get("status") == "completed")
    logger.info(f"[{scan_id}] Bulk enrichment done: {completed}/{len(results)} devices")
    return {
        "scan_id": scan_id,
        "status": "completed",
        "devices_enriched": completed,
        "total_devices": len(results),
        "completed_at": now_utc().isoformat(),
    }
