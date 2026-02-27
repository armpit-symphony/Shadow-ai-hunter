"""
Detection Worker for Shadow AI Hunter

Runs multi-layer detection on normalized telemetry events:
  1. Signature-based: matches known AI service domains / TLS SNI / IPs
  2. Heuristic-based: data-volume thresholds, off-hours access, user-agent patterns
  3. Evidence bundles: tamper-evident SHA-256 hash of supporting events

Designed to be called by the RQ worker queue or directly for testing.
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Comprehensive AI service signature database
# Grouped by category; all domains are lowercase.
# severity: critical = high-value data exfiltration risk
#           high = unauthorized external LLM/AI API usage
#           medium = developer/productivity AI tool
#           low = AI-adjacent or open-source adjacent
# ---------------------------------------------------------------------------

AI_SERVICE_SIGNATURES: Dict[str, Dict] = {
    # ── Large Language Models / Chat AI ──────────────────────────────────────
    "api.openai.com": {"name": "OpenAI API", "category": "llm", "severity": "critical"},
    "openai.com": {"name": "OpenAI", "category": "llm", "severity": "high"},
    "chat.openai.com": {"name": "ChatGPT", "category": "llm", "severity": "high"},
    "platform.openai.com": {"name": "OpenAI Platform", "category": "llm", "severity": "high"},
    "api.anthropic.com": {"name": "Anthropic API", "category": "llm", "severity": "critical"},
    "claude.ai": {"name": "Claude AI", "category": "llm", "severity": "high"},
    "anthropic.com": {"name": "Anthropic", "category": "llm", "severity": "high"},
    "generativelanguage.googleapis.com": {"name": "Google Gemini API", "category": "llm", "severity": "critical"},
    "aistudio.google.com": {"name": "Google AI Studio", "category": "llm", "severity": "high"},
    "gemini.google.com": {"name": "Google Gemini", "category": "llm", "severity": "high"},
    "bard.google.com": {"name": "Google Bard (legacy)", "category": "llm", "severity": "medium"},
    "api.mistral.ai": {"name": "Mistral API", "category": "llm", "severity": "critical"},
    "mistral.ai": {"name": "Mistral AI", "category": "llm", "severity": "high"},
    "api.cohere.ai": {"name": "Cohere API", "category": "llm", "severity": "critical"},
    "cohere.com": {"name": "Cohere", "category": "llm", "severity": "high"},
    "api.ai21.com": {"name": "AI21 Labs API", "category": "llm", "severity": "high"},
    "ai21.com": {"name": "AI21 Labs", "category": "llm", "severity": "medium"},
    "api.together.xyz": {"name": "Together AI API", "category": "llm", "severity": "high"},
    "together.ai": {"name": "Together AI", "category": "llm", "severity": "medium"},
    "api.fireworks.ai": {"name": "Fireworks AI API", "category": "llm", "severity": "high"},
    "fireworks.ai": {"name": "Fireworks AI", "category": "llm", "severity": "medium"},
    "api.groq.com": {"name": "Groq API", "category": "llm", "severity": "high"},
    "groq.com": {"name": "Groq", "category": "llm", "severity": "medium"},
    "api.perplexity.ai": {"name": "Perplexity API", "category": "llm", "severity": "high"},
    "perplexity.ai": {"name": "Perplexity AI", "category": "llm", "severity": "medium"},
    "you.com": {"name": "You.com AI Search", "category": "llm", "severity": "low"},
    "poe.com": {"name": "Poe (multi-LLM)", "category": "llm", "severity": "medium"},
    "character.ai": {"name": "Character.AI", "category": "llm", "severity": "medium"},
    "api.deepseek.com": {"name": "DeepSeek API", "category": "llm", "severity": "high"},
    "chat.deepseek.com": {"name": "DeepSeek Chat", "category": "llm", "severity": "medium"},
    "deepseek.com": {"name": "DeepSeek", "category": "llm", "severity": "medium"},
    "api.x.ai": {"name": "xAI / Grok API", "category": "llm", "severity": "high"},
    "grok.x.ai": {"name": "Grok", "category": "llm", "severity": "medium"},
    "inflection.ai": {"name": "Inflection AI / Pi", "category": "llm", "severity": "medium"},
    "pi.ai": {"name": "Pi (Inflection)", "category": "llm", "severity": "low"},
    "api.aleph-alpha.com": {"name": "Aleph Alpha API", "category": "llm", "severity": "high"},
    "aleph-alpha.com": {"name": "Aleph Alpha", "category": "llm", "severity": "medium"},
    "nlpcloud.com": {"name": "NLP Cloud", "category": "llm", "severity": "medium"},
    "forefront.ai": {"name": "Forefront AI", "category": "llm", "severity": "medium"},
    "chat.lmsys.org": {"name": "LMSYS Chatbot Arena", "category": "llm", "severity": "low"},

    # ── Code AI / Developer Copilots ─────────────────────────────────────────
    "copilot-proxy.githubusercontent.com": {"name": "GitHub Copilot", "category": "code_ai", "severity": "high"},
    "githubcopilot.com": {"name": "GitHub Copilot", "category": "code_ai", "severity": "high"},
    "copilot.github.com": {"name": "GitHub Copilot", "category": "code_ai", "severity": "high"},
    "codeium.com": {"name": "Codeium", "category": "code_ai", "severity": "medium"},
    "api.codeium.com": {"name": "Codeium API", "category": "code_ai", "severity": "high"},
    "www.cursor.com": {"name": "Cursor IDE", "category": "code_ai", "severity": "medium"},
    "api2.cursor.sh": {"name": "Cursor AI API", "category": "code_ai", "severity": "high"},
    "cursor.sh": {"name": "Cursor", "category": "code_ai", "severity": "medium"},
    "tabnine.com": {"name": "Tabnine", "category": "code_ai", "severity": "medium"},
    "api.tabnine.com": {"name": "Tabnine API", "category": "code_ai", "severity": "high"},
    "sourcegraph.com": {"name": "Sourcegraph Cody", "category": "code_ai", "severity": "medium"},
    "cody.sourcegraph.com": {"name": "Sourcegraph Cody API", "category": "code_ai", "severity": "high"},
    "replit.com": {"name": "Replit AI", "category": "code_ai", "severity": "medium"},
    "ai.replit.com": {"name": "Replit AI Service", "category": "code_ai", "severity": "high"},
    "amazon.com": None,  # excluded - too broad; use specific subdomains below
    "codewhisperer.amazonaws.com": {"name": "AWS CodeWhisperer", "category": "code_ai", "severity": "high"},
    "q.amazonaws.com": {"name": "Amazon Q", "category": "code_ai", "severity": "high"},
    "devin.ai": {"name": "Devin AI Coder", "category": "code_ai", "severity": "high"},
    "magic.dev": {"name": "Magic AI Coder", "category": "code_ai", "severity": "medium"},

    # ── Image & Video Generation ──────────────────────────────────────────────
    "midjourney.com": {"name": "Midjourney", "category": "image_gen", "severity": "medium"},
    "api.stability.ai": {"name": "Stability AI API", "category": "image_gen", "severity": "high"},
    "stability.ai": {"name": "Stability AI", "category": "image_gen", "severity": "medium"},
    "dreamstudio.ai": {"name": "DreamStudio", "category": "image_gen", "severity": "medium"},
    "replicate.com": {"name": "Replicate", "category": "ml_inference", "severity": "high"},
    "api.replicate.com": {"name": "Replicate API", "category": "ml_inference", "severity": "critical"},
    "runway.com": {"name": "Runway ML", "category": "video_gen", "severity": "medium"},
    "runwayml.com": {"name": "Runway ML", "category": "video_gen", "severity": "medium"},
    "pika.art": {"name": "Pika Labs", "category": "video_gen", "severity": "low"},
    "kaiber.ai": {"name": "Kaiber AI", "category": "video_gen", "severity": "low"},
    "leonardo.ai": {"name": "Leonardo AI", "category": "image_gen", "severity": "medium"},
    "app.leonardo.ai": {"name": "Leonardo AI App", "category": "image_gen", "severity": "medium"},
    "firefly.adobe.com": {"name": "Adobe Firefly", "category": "image_gen", "severity": "medium"},
    "labs.openai.com": {"name": "DALL-E / OpenAI Labs", "category": "image_gen", "severity": "high"},
    "canva.com": None,  # too broad

    # ── Content / Writing AI ──────────────────────────────────────────────────
    "jasper.ai": {"name": "Jasper AI", "category": "content_ai", "severity": "medium"},
    "app.jasper.ai": {"name": "Jasper AI App", "category": "content_ai", "severity": "medium"},
    "copy.ai": {"name": "Copy.ai", "category": "content_ai", "severity": "low"},
    "writesonic.com": {"name": "Writesonic", "category": "content_ai", "severity": "low"},
    "rytr.me": {"name": "Rytr", "category": "content_ai", "severity": "low"},
    "anyword.com": {"name": "Anyword", "category": "content_ai", "severity": "low"},
    "grammarly.com": {"name": "Grammarly AI", "category": "content_ai", "severity": "low"},
    "notion.so": None,  # too broad, but Notion AI is notable
    "otter.ai": {"name": "Otter.ai Transcription", "category": "content_ai", "severity": "medium"},
    "meetgeek.ai": {"name": "MeetGeek AI", "category": "content_ai", "severity": "medium"},
    "fireflies.ai": {"name": "Fireflies.ai", "category": "content_ai", "severity": "medium"},

    # ── ML Infrastructure / Model Hosting ────────────────────────────────────
    "huggingface.co": {"name": "Hugging Face", "category": "ml_infra", "severity": "medium"},
    "api-inference.huggingface.co": {"name": "HuggingFace Inference API", "category": "ml_infra", "severity": "high"},
    "router.huggingface.co": {"name": "HuggingFace Router", "category": "ml_infra", "severity": "high"},
    "endpoints.huggingface.cloud": {"name": "HuggingFace Endpoints", "category": "ml_infra", "severity": "critical"},
    "wandb.ai": {"name": "Weights & Biases", "category": "ml_dev", "severity": "medium"},
    "api.wandb.ai": {"name": "W&B API", "category": "ml_dev", "severity": "high"},
    "app.neptune.ai": {"name": "Neptune.ai", "category": "ml_dev", "severity": "medium"},
    "mlflow.org": {"name": "MLflow", "category": "ml_dev", "severity": "low"},
    "vertexai.googleapis.com": {"name": "Google Vertex AI", "category": "ml_infra", "severity": "critical"},
    "aiplatform.googleapis.com": {"name": "Google AI Platform", "category": "ml_infra", "severity": "critical"},
    "bedrock.amazonaws.com": {"name": "AWS Bedrock", "category": "ml_infra", "severity": "critical"},
    "bedrock-runtime.amazonaws.com": {"name": "AWS Bedrock Runtime", "category": "ml_infra", "severity": "critical"},
    "cognitiveservices.azure.com": {"name": "Azure Cognitive Services", "category": "ml_infra", "severity": "high"},
    "openai.azure.com": {"name": "Azure OpenAI", "category": "llm", "severity": "critical"},
    "inference.azure.com": {"name": "Azure AI Inference", "category": "ml_infra", "severity": "high"},
    "modal.com": {"name": "Modal AI Compute", "category": "ml_infra", "severity": "medium"},
    "api.modal.com": {"name": "Modal API", "category": "ml_infra", "severity": "high"},
    "vast.ai": {"name": "Vast.ai GPU Rental", "category": "ml_infra", "severity": "medium"},

    # ── AI Agent / Automation Platforms ──────────────────────────────────────
    "api.langchain.com": {"name": "LangChain API", "category": "ai_agent", "severity": "high"},
    "smith.langchain.com": {"name": "LangSmith", "category": "ai_agent", "severity": "medium"},
    "api.langsmith.com": {"name": "LangSmith API", "category": "ai_agent", "severity": "high"},
    "api.openrouter.ai": {"name": "OpenRouter API", "category": "llm", "severity": "high"},
    "openrouter.ai": {"name": "OpenRouter", "category": "llm", "severity": "medium"},
    "app.relevanceai.com": {"name": "Relevance AI", "category": "ai_agent", "severity": "medium"},
    "api.relevanceai.com": {"name": "Relevance AI API", "category": "ai_agent", "severity": "high"},
    "dust.tt": {"name": "Dust AI", "category": "ai_agent", "severity": "medium"},
    "agentgpt.reworkd.ai": {"name": "AgentGPT", "category": "ai_agent", "severity": "medium"},
    "dify.ai": {"name": "Dify.ai", "category": "ai_agent", "severity": "medium"},
    "flowise.ai": {"name": "Flowise AI", "category": "ai_agent", "severity": "medium"},
    "n8n.io": {"name": "n8n AI Workflows", "category": "ai_agent", "severity": "low"},
    "zapier.com": None,  # too broad

    # ── AI Search ─────────────────────────────────────────────────────────────
    "api.tavily.com": {"name": "Tavily AI Search API", "category": "ai_search", "severity": "medium"},
    "tavily.com": {"name": "Tavily AI Search", "category": "ai_search", "severity": "low"},
    "metaphor.systems": {"name": "Metaphor AI Search", "category": "ai_search", "severity": "low"},
    "exa.ai": {"name": "Exa AI Search", "category": "ai_search", "severity": "low"},

    # ── AI-Powered Meeting / Voice ────────────────────────────────────────────
    "rev.ai": {"name": "Rev.ai Transcription", "category": "voice_ai", "severity": "medium"},
    "api.assemblyai.com": {"name": "AssemblyAI API", "category": "voice_ai", "severity": "high"},
    "assemblyai.com": {"name": "AssemblyAI", "category": "voice_ai", "severity": "medium"},
    "api.elevenlabs.io": {"name": "ElevenLabs TTS API", "category": "voice_ai", "severity": "high"},
    "elevenlabs.io": {"name": "ElevenLabs", "category": "voice_ai", "severity": "medium"},
    "api.deepgram.com": {"name": "Deepgram API", "category": "voice_ai", "severity": "high"},
    "deepgram.com": {"name": "Deepgram", "category": "voice_ai", "severity": "medium"},
    "murf.ai": {"name": "Murf AI Voice", "category": "voice_ai", "severity": "low"},
}

# Remove entries intentionally excluded (set to None)
AI_SERVICE_SIGNATURES = {k: v for k, v in AI_SERVICE_SIGNATURES.items() if v is not None}

# ---------------------------------------------------------------------------
# User-agent patterns that indicate AI client tools
# ---------------------------------------------------------------------------

AI_USER_AGENT_PATTERNS: List[str] = [
    r"openai-python",
    r"anthropic-sdk",
    r"openai/",
    r"claude-",
    r"langchain",
    r"llama_index",
    r"llamaindex",
    r"huggingface",
    r"transformers/",
    r"copilot",
    r"codeium",
    r"tabnine",
    r"cursor/",
    r"ollama",
    r"localai",
    r"gpt4all",
]

# Compiled regexes for performance
_UA_REGEXES = [re.compile(p, re.IGNORECASE) for p in AI_USER_AGENT_PATTERNS]

# ---------------------------------------------------------------------------
# Allowlist: domains that should never generate findings
# Loaded from environment or DB; extend per-deployment.
# ---------------------------------------------------------------------------

_DEFAULT_ALLOWLIST: List[str] = [
    "ai.company-internal.local",
    "internal-llm.corp",
]


def get_db():
    """Get a direct MongoDB connection for use inside worker processes."""
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
    from pymongo import MongoClient

    client = MongoClient(mongo_url, serverSelectionTimeoutMS=3000)
    return client, client.shadow_ai_hunter


def _domain_matches_list(domain: str, items: List[str]) -> bool:
    for entry in items:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.startswith("*."):
            suffix = entry[2:]
            if domain == suffix or domain.endswith(f".{suffix}"):
                return True
        else:
            if domain == entry or domain.endswith(f".{entry}"):
                return True
    return False


def _load_list_from_db(list_id: str) -> List[str]:
    try:
        client, db = get_db()
        doc = db.lists.find_one({"_id": list_id})
        client.close()
        if doc and isinstance(doc.get("items"), list):
            return [str(x).strip().lower() for x in doc["items"] if str(x).strip()]
    except Exception:
        return []
    return []


def _load_baselines_from_db() -> Dict[str, Dict]:
    try:
        client, db = get_db()
        docs = list(db.baselines.find({}, {"_id": 0}))
        client.close()
        baseline_map = {}
        for d in docs:
            segment = d.get("segment")
            if segment:
                baseline_map[segment] = d
        return baseline_map
    except Exception:
        return {}


def _event_segment(event: Dict) -> str:
    return (
        event.get("segment")
        or event.get("network_segment")
        or event.get("network_range")
        or "default"
    )

def load_allowlist() -> List[str]:
    """Load allowlisted domains from environment variable (comma-separated) or defaults."""
    db_items = _load_list_from_db("allowlist")
    env_list = os.getenv("AI_DETECTION_ALLOWLIST", "")
    extra = [d.strip().lower() for d in env_list.split(",") if d.strip()]
    return list(dict.fromkeys(db_items + _DEFAULT_ALLOWLIST + extra))


def load_denylist() -> List[str]:
    """Load denylisted domains from DB or environment variable."""
    db_items = _load_list_from_db("denylist")
    env_list = os.getenv("AI_DETECTION_DENYLIST", "")
    extra = [d.strip().lower() for d in env_list.split(",") if d.strip()]
    return list(dict.fromkeys(db_items + extra))


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def detect_ai_services(
    event: Dict,
    allowlist: Optional[List[str]] = None,
    denylist: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Signature-based detection: check an event's domain/SNI/URL against the
    AI service signature database. Returns a list of finding dicts.
    """
    if allowlist is None:
        allowlist = load_allowlist()
    if denylist is None:
        denylist = load_denylist()

    findings = []

    def _check_domain(domain: str, match_type: str) -> None:
        if not domain:
            return
        domain = domain.lower().strip()
        # Denylist check first (override allowlist)
        if _domain_matches_list(domain, denylist):
            findings.append({
                "type": "denylist",
                "indicator": domain,
                "service": "Denylisted Domain",
                "category": "denylist",
                "severity": "critical",
                "confidence": 1.0,
                "details": "Domain is explicitly denylisted",
            })
            return
        # Allowlist check
        if _domain_matches_list(domain, allowlist):
            return
        sig = AI_SERVICE_SIGNATURES.get(domain)
        if sig:
            findings.append({
                "type": match_type,
                "indicator": domain,
                "service": sig["name"],
                "category": sig["category"],
                "severity": sig["severity"],
                "confidence": 0.95,
            })

    _check_domain(event.get("dest_domain", ""), "ai_domain_match")
    _check_domain(event.get("tls_sni", ""), "ai_sni_match")

    # Also try to extract domain from a raw URL field
    url = event.get("url", "")
    if url and "://" in url:
        from workers.telemetry_worker import extract_domain
        _check_domain(extract_domain(url), "ai_url_match")

    return findings


def detect_ai_user_agents(event: Dict) -> List[Dict]:
    """
    Heuristic: check the User-Agent header for known AI SDK / client patterns.
    """
    ua = event.get("user_agent", "") or ""
    for regex in _UA_REGEXES:
        if regex.search(ua):
            return [
                {
                    "type": "ai_user_agent",
                    "indicator": ua[:200],
                    "severity": "medium",
                    "confidence": 0.75,
                    "pattern": regex.pattern,
                }
            ]
    return []


def heuristic_detection(event: Dict, baseline: Optional[Dict] = None) -> List[Dict]:
    """
    Heuristic rules that go beyond signature matching.
    Returns additional finding dicts.
    """
    findings = []
    dest = event.get("dest_domain", "").lower()
    is_known_ai = dest in AI_SERVICE_SIGNATURES

    # H1: High-volume data upload to a known AI endpoint
    bytes_out = event.get("bytes_out", 0)
    if is_known_ai and bytes_out > 500_000:  # > 500 KB
        findings.append({
            "type": "high_volume_upload",
            "indicator": f"{dest} — {bytes_out:,} bytes sent",
            "severity": "high" if bytes_out > 2_000_000 else "medium",
            "confidence": 0.80,
        })

    # H2: Off-hours access to AI endpoint (naive: treat hour 0-6 as off-hours)
    try:
        ts = datetime.fromisoformat(str(event.get("ts", "")))
        if is_known_ai and ts.hour < 6:
            findings.append({
                "type": "off_hours_ai_access",
                "indicator": f"{dest} accessed at {ts.strftime('%H:%M')} UTC",
                "severity": "medium",
                "confidence": 0.55,
            })
    except Exception:
        pass

    # H3: Known AI domain not seen in baseline
    if baseline and dest and dest in AI_SERVICE_SIGNATURES:
        if dest not in baseline.get("known_ai_domains", []):
            findings.append({
                "type": "new_ai_destination",
                "indicator": dest,
                "severity": "medium",
                "confidence": 0.60,
            })

    # H4: AI user-agent
    findings.extend(detect_ai_user_agents(event))

    return findings


def compute_risk_score(findings: List[Dict], asset_criticality: float = 0.7) -> float:
    """
    Compute a 0–1 risk score from a list of findings.
    Formula: max_severity_weight × max_confidence × asset_criticality,
    with a bonus for multiple independent findings (up to +0.1).
    """
    if not findings:
        return 0.0

    severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
    max_sev = max(severity_weights.get(f.get("severity", "low"), 0.2) for f in findings)
    max_conf = max(f.get("confidence", 0.5) for f in findings)
    count_bonus = min(0.1, len(findings) * 0.02)

    return min(1.0, max_sev * max_conf * asset_criticality + count_bonus)


def create_evidence_bundle(events: List[Dict], findings: List[Dict]) -> Dict:
    """
    Create a tamper-evident evidence bundle for an alert or detection record.
    The SHA-256 hash covers the sorted JSON of the raw events so it can be
    verified later during an incident investigation.
    """
    try:
        events_json = json.dumps(events, sort_keys=True, default=str)
        evidence_hash = hashlib.sha256(events_json.encode()).hexdigest()
    except Exception:
        evidence_hash = "hash-error"

    return {
        "created_at": now_utc().isoformat(),
        "event_count": len(events),
        "finding_count": len(findings),
        "event_ids": [str(e.get("id", e.get("_id", "unknown"))) for e in events],
        "findings": findings,
        "evidence_hash": evidence_hash,
    }


def run_detection(scan_id: str, events: List[Dict]) -> Dict:
    """
    Main detection worker entry point (called by RQ or async fallback).

    1. Runs signature + heuristic detection on every event.
    2. Groups findings by source device (IP).
    3. Persists per-device detection results and alerts to MongoDB.
    4. Returns a summary dict.
    """
    logger.info(f"[{scan_id}] Running detection on {len(events)} events")

    allowlist = load_allowlist()
    denylist = load_denylist()
    baselines = _load_baselines_from_db()
    all_findings: List[Dict] = []
    # Group events by source IP for per-device risk computation
    device_events: Dict[str, List[Dict]] = {}

    for event in events:
        sig_findings = detect_ai_services(event, allowlist=allowlist, denylist=denylist)
        baseline = baselines.get(_event_segment(event)) or baselines.get("default")
        heur_findings = heuristic_detection(event, baseline=baseline)
        event_findings = sig_findings + heur_findings
        all_findings.extend(event_findings)

        src = event.get("source", event.get("source_ip", "unknown"))
        if src not in device_events:
            device_events[src] = []
        if event_findings:
            device_events[src].append({"event": event, "findings": event_findings})

    # Persist to MongoDB if available
    try:
        mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
        from pymongo import MongoClient as _MC

        _client = _MC(mongo_url, serverSelectionTimeoutMS=3000)
        _db = _client.shadow_ai_hunter

        for src_ip, device_data in device_events.items():
            flat_findings = [f for d in device_data for f in d["findings"]]
            flat_events = [d["event"] for d in device_data]
            risk_score = compute_risk_score(flat_findings)
            evidence = create_evidence_bundle(flat_events, flat_findings)
            ai_services = list({f.get("service") for f in flat_findings if f.get("service")})

            _db.devices.update_one(
                {"ip_address": src_ip},
                {
                    "$set": {
                        "ip_address": src_ip,
                        "ai_risk_score": risk_score,
                        "ai_services_detected": ai_services,
                        "last_detection": now_utc(),
                        "last_evidence": evidence,
                        "status": "active",
                    }
                },
                upsert=True,
            )

            if risk_score >= 0.5:
                alert = {
                    "title": f"AI Usage Detected — {src_ip}",
                    "description": (
                        f"Device {src_ip} accessed {len(ai_services)} AI service(s): "
                        f"{', '.join(ai_services[:5])}"
                    ),
                    "severity": (
                        "critical" if risk_score >= 0.85 else
                        "high" if risk_score >= 0.65 else "medium"
                    ),
                    "device_ip": src_ip,
                    "alert_type": "ai_detection",
                    "evidence": evidence,
                    "scan_id": scan_id,
                    "created_at": now_utc(),
                    "resolved": False,
                }
                _db.alerts.insert_one(alert)

        _db.scans.update_one(
            {"_id": scan_id, "status": {"$in": ["queued_detection", "processing", "running", "completed"]}},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": now_utc(),
                    "findings_count": len(all_findings),
                    "devices_with_findings": len(device_events),
                }
            },
        )
        try:
            _db.ws_events.insert_one({
                "type": "detection_completed",
                "scan_id": scan_id,
                "findings_count": len(all_findings),
                "devices_with_findings": len(device_events),
                "status": "completed",
                "created_at": now_utc(),
            })
        except Exception:
            pass
        _client.close()
    except Exception as e:
        logger.warning(f"[{scan_id}] Could not persist detection results: {e}")

    result = {
        "scan_id": scan_id,
        "status": "completed",
        "events_processed": len(events),
        "findings_count": len(all_findings),
        "devices_with_findings": len(device_events),
        "risk_score": compute_risk_score(all_findings),
        "evidence": create_evidence_bundle(events, all_findings),
        "completed_at": now_utc().isoformat(),
    }

    logger.info(
        f"[{scan_id}] Detection done: {len(all_findings)} findings across "
        f"{len(device_events)} devices"
    )
    return result
