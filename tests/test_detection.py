"""
Unit tests for backend/workers/detector_worker.py

Run with:  cd backend && pytest ../tests/test_detection.py -v
"""

import sys
import os

# Ensure backend/ is on the path so detector_worker can be imported
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend", "workers"))

import pytest

from detector_worker import (
    AI_SERVICE_SIGNATURES,
    detect_ai_services,
    detect_ai_user_agents,
    heuristic_detection,
    compute_risk_score,
    create_evidence_bundle,
    run_detection,
)


# ---------------------------------------------------------------------------
# Signature coverage
# ---------------------------------------------------------------------------

class TestSignatureCoverage:
    def test_minimum_signature_count(self):
        """We should have at least 80 known AI service domains."""
        assert len(AI_SERVICE_SIGNATURES) >= 80, (
            f"Only {len(AI_SERVICE_SIGNATURES)} signatures — add more coverage"
        )

    def test_required_categories_present(self):
        categories = {v["category"] for v in AI_SERVICE_SIGNATURES.values()}
        for expected in ("llm", "code_ai", "image_gen", "ml_infra"):
            assert expected in categories, f"Category '{expected}' missing from signatures"

    def test_openai_api_is_critical(self):
        assert AI_SERVICE_SIGNATURES["api.openai.com"]["severity"] == "critical"

    def test_anthropic_api_is_critical(self):
        assert AI_SERVICE_SIGNATURES["api.anthropic.com"]["severity"] == "critical"

    def test_no_none_values(self):
        for domain, sig in AI_SERVICE_SIGNATURES.items():
            assert sig is not None, f"Signature for {domain!r} is None (should be filtered)"
            assert "name" in sig
            assert "category" in sig
            assert "severity" in sig


# ---------------------------------------------------------------------------
# Signature-based detection
# ---------------------------------------------------------------------------

class TestDetectAiServices:
    def test_known_llm_api_domain(self):
        event = {"dest_domain": "api.openai.com", "source_ip": "192.168.1.10"}
        findings = detect_ai_services(event)
        assert len(findings) == 1
        assert findings[0]["service"] == "OpenAI API"
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] >= 0.9

    def test_tls_sni_detection(self):
        event = {"tls_sni": "claude.ai", "source_ip": "192.168.1.20"}
        findings = detect_ai_services(event)
        assert len(findings) == 1
        assert "Claude" in findings[0]["service"]

    def test_url_extraction(self):
        event = {"url": "https://api.anthropic.com/v1/messages", "source_ip": "10.0.1.5"}
        findings = detect_ai_services(event)
        assert any("Anthropic" in f["service"] for f in findings)

    def test_no_finding_for_unknown_domain(self):
        event = {"dest_domain": "example.com", "source_ip": "192.168.1.1"}
        findings = detect_ai_services(event)
        assert findings == []

    def test_allowlist_suppresses_finding(self):
        event = {"dest_domain": "api.openai.com", "source_ip": "10.0.0.1"}
        allowlist = ["api.openai.com"]
        findings = detect_ai_services(event, allowlist=allowlist)
        assert findings == [], "Allowlisted domain should not produce a finding"

    def test_subdomain_not_matched_to_parent(self):
        # "chat.openai.com" is explicitly in signatures, but a random subdomain is not
        event = {"dest_domain": "random.openai.com"}
        findings = detect_ai_services(event)
        # random.openai.com is not in the signature list directly
        assert not any(f["indicator"] == "random.openai.com" for f in findings)

    def test_empty_event(self):
        findings = detect_ai_services({})
        assert findings == []

    def test_multiple_indicators_same_event(self):
        event = {
            "dest_domain": "api.openai.com",
            "tls_sni": "api.openai.com",
        }
        findings = detect_ai_services(event)
        # Both domain and SNI match — we expect 2 findings
        assert len(findings) == 2

    def test_huggingface_inference_api_is_critical(self):
        event = {"dest_domain": "endpoints.huggingface.cloud"}
        findings = detect_ai_services(event)
        assert len(findings) == 1
        assert findings[0]["severity"] == "critical"

    def test_code_ai_category(self):
        event = {"dest_domain": "copilot-proxy.githubusercontent.com"}
        findings = detect_ai_services(event)
        assert findings[0]["category"] == "code_ai"


# ---------------------------------------------------------------------------
# User-agent detection
# ---------------------------------------------------------------------------

class TestDetectAiUserAgents:
    def test_openai_python_sdk(self):
        event = {"user_agent": "openai-python/1.10.0 Python/3.11"}
        findings = detect_ai_user_agents(event)
        assert len(findings) == 1
        assert findings[0]["type"] == "ai_user_agent"

    def test_langchain_user_agent(self):
        event = {"user_agent": "langchain/0.2.0"}
        findings = detect_ai_user_agents(event)
        assert len(findings) == 1

    def test_normal_browser_no_finding(self):
        event = {"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        findings = detect_ai_user_agents(event)
        assert findings == []

    def test_empty_user_agent(self):
        findings = detect_ai_user_agents({})
        assert findings == []


# ---------------------------------------------------------------------------
# Heuristic detection
# ---------------------------------------------------------------------------

class TestHeuristicDetection:
    def test_high_volume_upload(self):
        event = {
            "dest_domain": "api.openai.com",
            "bytes_out": 2_000_001,
            "ts": "2026-02-27T14:00:00",
        }
        findings = heuristic_detection(event)
        types = [f["type"] for f in findings]
        assert "high_volume_upload" in types

    def test_small_upload_no_finding(self):
        event = {
            "dest_domain": "api.openai.com",
            "bytes_out": 1_000,
            "ts": "2026-02-27T14:00:00",
        }
        findings = heuristic_detection(event)
        volume_findings = [f for f in findings if f["type"] == "high_volume_upload"]
        assert volume_findings == []

    def test_off_hours_access(self):
        event = {
            "dest_domain": "api.openai.com",
            "ts": "2026-02-27T03:00:00",
        }
        findings = heuristic_detection(event)
        off_hours = [f for f in findings if f["type"] == "off_hours_ai_access"]
        assert len(off_hours) == 1

    def test_new_ai_destination(self):
        event = {"dest_domain": "api.groq.com", "ts": "2026-02-27T10:00:00"}
        baseline = {"known_ai_domains": ["api.openai.com"]}
        findings = heuristic_detection(event, baseline=baseline)
        new_dest = [f for f in findings if f["type"] == "new_ai_destination"]
        assert len(new_dest) == 1

    def test_known_domain_in_baseline_no_new_finding(self):
        event = {"dest_domain": "api.openai.com", "ts": "2026-02-27T10:00:00"}
        baseline = {"known_ai_domains": ["api.openai.com"]}
        findings = heuristic_detection(event, baseline=baseline)
        new_dest = [f for f in findings if f["type"] == "new_ai_destination"]
        assert new_dest == []


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    def test_empty_findings_zero_score(self):
        assert compute_risk_score([]) == 0.0

    def test_critical_finding_high_score(self):
        findings = [{"severity": "critical", "confidence": 1.0}]
        score = compute_risk_score(findings, asset_criticality=1.0)
        assert score >= 0.9

    def test_low_severity_low_score(self):
        findings = [{"severity": "low", "confidence": 0.5}]
        score = compute_risk_score(findings, asset_criticality=0.5)
        assert score < 0.3

    def test_score_capped_at_one(self):
        findings = [{"severity": "critical", "confidence": 1.0}] * 20
        score = compute_risk_score(findings, asset_criticality=1.0)
        assert score <= 1.0

    def test_multiple_findings_higher_than_single(self):
        single = compute_risk_score(
            [{"severity": "high", "confidence": 0.8}]
        )
        multiple = compute_risk_score(
            [{"severity": "high", "confidence": 0.8}] * 5
        )
        assert multiple >= single


# ---------------------------------------------------------------------------
# Evidence bundle
# ---------------------------------------------------------------------------

class TestCreateEvidenceBundle:
    def test_bundle_has_required_fields(self):
        events = [{"id": "evt-1", "dest_domain": "api.openai.com"}]
        findings = [{"type": "ai_domain_match", "severity": "critical"}]
        bundle = create_evidence_bundle(events, findings)

        assert "created_at" in bundle
        assert "evidence_hash" in bundle
        assert bundle["event_count"] == 1
        assert bundle["finding_count"] == 1

    def test_hash_is_sha256_hex(self):
        events = [{"id": "x"}]
        bundle = create_evidence_bundle(events, [])
        assert len(bundle["evidence_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in bundle["evidence_hash"])

    def test_same_events_same_hash(self):
        events = [{"id": "a", "domain": "test.com"}]
        b1 = create_evidence_bundle(events, [])
        b2 = create_evidence_bundle(events, [])
        assert b1["evidence_hash"] == b2["evidence_hash"]

    def test_different_events_different_hash(self):
        b1 = create_evidence_bundle([{"id": "a"}], [])
        b2 = create_evidence_bundle([{"id": "b"}], [])
        assert b1["evidence_hash"] != b2["evidence_hash"]

    def test_empty_events(self):
        bundle = create_evidence_bundle([], [])
        assert bundle["event_count"] == 0
        assert "evidence_hash" in bundle


# ---------------------------------------------------------------------------
# run_detection (no-DB path)
# ---------------------------------------------------------------------------

class TestRunDetection:
    def test_returns_summary_structure(self, monkeypatch):
        # Patch out MongoDB so the worker runs without a real DB
        monkeypatch.setenv("MONGO_URL", "mongodb://localhost:99999/nodb")

        events = [
            {"source_ip": "192.168.1.5", "dest_domain": "api.openai.com", "ts": "2026-02-27T10:00:00"},
            {"source_ip": "192.168.1.5", "dest_domain": "claude.ai", "ts": "2026-02-27T11:00:00"},
            {"source_ip": "10.0.0.1", "dest_domain": "example.com", "ts": "2026-02-27T12:00:00"},
        ]
        result = run_detection("test-scan-001", events)

        assert result["scan_id"] == "test-scan-001"
        assert result["events_processed"] == 3
        assert result["findings_count"] >= 2  # at least openai + claude
        assert "evidence" in result
        assert "risk_score" in result

    def test_empty_events(self, monkeypatch):
        monkeypatch.setenv("MONGO_URL", "mongodb://localhost:99999/nodb")
        result = run_detection("empty-scan", [])
        assert result["findings_count"] == 0
        assert result["risk_score"] == 0.0
