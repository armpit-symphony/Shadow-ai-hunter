"""
Report Worker for Shadow AI Hunter

Generates security reports in JSON and PDF formats.
PDF is produced with fpdf2 (already in requirements.txt).
Falls back to plain-text if fpdf2 is unavailable.
"""

import hashlib
import json
import logging
import os
import re
import requests
from datetime import datetime, timezone
from typing import Dict, List

logger = logging.getLogger(__name__)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _mask_ip(value: str) -> str:
    if ":" in value:
        parts = value.split(":")
        return ":".join(parts[:-1] + ["xxxx"])
    parts = value.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["xxx"])
    return value


def _mask_email(value: str) -> str:
    if "@" not in value:
        return value
    name, domain = value.split("@", 1)
    if not name:
        return "***@" + domain
    return name[0] + "***@" + domain


def _mask_user(value: str) -> str:
    if not value:
        return value
    return value[0] + "***"


def _mask_text(value: str) -> str:
    if not isinstance(value, str):
        return value
    value = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", lambda m: _mask_ip(m.group(0)), value)
    value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", lambda m: _mask_email(m.group(0)), value)
    return value


def _mask_findings(findings: List[Dict]) -> List[Dict]:
    masked = []
    for f in findings:
        nf = {}
        for k, v in f.items():
            if k in {"device_ip", "source", "dest_ip"} and isinstance(v, str):
                nf[k] = _mask_ip(v)
            elif k in {"user", "username"} and isinstance(v, str):
                nf[k] = _mask_user(v)
            elif k == "indicator" and isinstance(v, str):
                nf[k] = _mask_text(v)
            elif isinstance(v, str):
                nf[k] = _mask_text(v)
            else:
                nf[k] = v
        masked.append(nf)
    return masked


def _mask_report(report: Dict) -> Dict:
    masked = dict(report)
    masked["scan_details"] = {
        k: _mask_text(str(v)) for k, v in report.get("scan_details", {}).items()
    }
    masked["findings"] = _mask_findings(report.get("findings", []))
    return masked


def get_db():
    mongo_url = os.getenv("MONGO_URL", "mongodb://localhost:27017/shadow_ai_hunter")
    from pymongo import MongoClient

    client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
    return client, client.shadow_ai_hunter


# ---------------------------------------------------------------------------
# Risk helpers
# ---------------------------------------------------------------------------

def calculate_risk_level(findings: List[Dict]) -> str:
    """Map a list of findings to an overall risk label."""
    if not findings:
        return "low"
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1
    if counts["critical"] > 0:
        return "critical"
    if counts["high"] > 0:
        return "high"
    if counts["medium"] > 0:
        return "medium"
    return "low"


def generate_compliance_summary(findings: List[Dict]) -> Dict:
    """Summarise compliance impact by category."""
    categories: Dict[str, int] = {}
    for f in findings:
        cat = f.get("category", f.get("type", "unknown"))
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "categories": categories,
        "gdpr_impact": "high" if categories.get("llm", 0) > 0 else "low",
        "hipaa_impact": "medium" if categories.get("healthcare", 0) > 0 else "low",
        "total_violations": len(findings),
        "nist_ai_rmf_functions": {
            "GOVERN": "Review AI usage policies and update AI inventory",
            "MAP": f"Map {len(categories)} AI service categories to risk tier",
            "MEASURE": f"{len(findings)} findings require measurement/monitoring",
            "MANAGE": "Apply block/monitor policies per enforcement plan",
        },
    }


def generate_recommendations(findings: List[Dict]) -> List[str]:
    """Generate actionable recommendations from findings."""
    recs: List[str] = []

    ai_domain_findings = [f for f in findings if "domain" in f.get("type", "") or "sni" in f.get("type", "")]
    port_findings = [f for f in findings if "port" in f.get("type", "")]
    volume_findings = [f for f in findings if f.get("type") == "high_volume_upload"]
    policy_findings = [f for f in findings if f.get("alert_type") == "policy_violation"]

    if ai_domain_findings:
        recs.append(
            f"Block {len(ai_domain_findings)} unauthorised AI service domain(s) at the DNS "
            "resolver or secure web gateway. Implement a DNS allowlist for approved AI services."
        )
    if port_findings:
        recs.append(
            f"Review {len(port_findings)} device(s) with locally-running AI services. "
            "Require IT registration and security review before allowing these workloads."
        )
    if volume_findings:
        recs.append(
            f"Investigate {len(volume_findings)} high-volume data transfer(s) to AI endpoints. "
            "Update Data Loss Prevention (DLP) policies to restrict sensitive data uploads."
        )
    if policy_findings:
        recs.append(
            f"{len(policy_findings)} policy violation(s) detected. "
            "Escalate to security team and initiate the Shadow AI response playbook."
        )
    if not recs:
        recs.append(
            "No immediate action required. Continue monitoring and keep AI service signatures up to date."
        )
    return recs


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(scan_id: str, scan_data: Dict, findings: List[Dict]) -> Dict:
    """Build a structured JSON report with integrity hash."""
    report: Dict = {
        "report_id": f"rpt-{scan_id[:8]}-{now_utc().strftime('%Y%m%d%H%M%S')}",
        "scan_id": scan_id,
        "generated_at": now_utc().isoformat(),
        "schema_version": "2.0",
        "summary": {
            "total_events": scan_data.get("events_processed", scan_data.get("devices_found", 0)),
            "findings_count": len(findings),
            "risk_level": calculate_risk_level(findings),
            "devices_with_findings": scan_data.get("devices_with_findings", 0),
        },
        "scan_details": {k: str(v) for k, v in scan_data.items() if k != "_id"},
        "findings": findings,
        "compliance_summary": generate_compliance_summary(findings),
        "recommendations": generate_recommendations(findings),
    }
    if os.getenv("REPORT_MASK_PII", "false").lower() == "true":
        report = _mask_report(report)
    # Integrity hash (covers findings only — stable even if metadata changes)
    report["integrity_hash"] = hashlib.sha256(
        json.dumps(findings, sort_keys=True, default=str).encode()
    ).hexdigest()
    return report


# ---------------------------------------------------------------------------
# PDF report (fpdf2)
# ---------------------------------------------------------------------------

def generate_pdf_content(report: Dict) -> bytes:
    """Generate a real PDF report using fpdf2."""
    try:
        from fpdf import FPDF  # fpdf2

        class _PDF(FPDF):
            def header(self):
                self.set_font("Helvetica", "B", 10)
                self.set_fill_color(30, 30, 60)
                self.set_text_color(255, 255, 255)
                self.cell(0, 10, "Shadow AI Hunter — Enterprise Security Report", ln=True,
                          fill=True, align="C")
                self.set_text_color(0, 0, 0)
                self.ln(2)

            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 10, f"Page {self.page_no()} — CONFIDENTIAL", align="C")

        pdf = _PDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # ── Title block ──────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Security Scan Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Report ID: {report.get('report_id', 'N/A')}", ln=True, align="C")
        pdf.cell(0, 6, f"Generated: {report.get('generated_at', 'N/A')}", ln=True, align="C")
        pdf.ln(5)

        # ── Summary table ────────────────────────────────────────────────────
        summary = report.get("summary", {})
        risk_level = summary.get("risk_level", "unknown").upper()

        # Risk level colour
        risk_colours = {
            "CRITICAL": (200, 0, 0),
            "HIGH": (220, 80, 0),
            "MEDIUM": (200, 160, 0),
            "LOW": (0, 160, 0),
        }
        r, g, b = risk_colours.get(risk_level, (80, 80, 80))

        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 8, "Executive Summary", ln=True, fill=True)
        pdf.set_font("Helvetica", "", 10)

        rows = [
            ("Total Events / Devices", str(summary.get("total_events", 0))),
            ("Findings Count", str(summary.get("findings_count", 0))),
            ("Devices with Findings", str(summary.get("devices_with_findings", 0))),
        ]
        for label, value in rows:
            pdf.cell(90, 7, label, border=1)
            pdf.cell(100, 7, value, border=1, ln=True)

        # Risk level cell with colour
        pdf.cell(90, 7, "Overall Risk Level", border=1)
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(100, 7, risk_level, border=1, ln=True, fill=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        # ── Recommendations ──────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 8, "Recommendations", ln=True, fill=True)
        pdf.set_font("Helvetica", "", 10)
        for i, rec in enumerate(report.get("recommendations", []), 1):
            pdf.set_x(15)
            pdf.multi_cell(0, 6, f"{i}. {rec}")
            pdf.ln(1)
        pdf.ln(3)

        # ── Findings ─────────────────────────────────────────────────────────
        findings = report.get("findings", [])
        if findings:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 8, f"Findings ({len(findings)} total)", ln=True, fill=True)
            pdf.set_font("Helvetica", "", 9)

            # Table header
            pdf.set_fill_color(60, 60, 100)
            pdf.set_text_color(255, 255, 255)
            for col, w in [("Type", 45), ("Severity", 25), ("Indicator", 80), ("Confidence", 25)]:
                pdf.cell(w, 7, col, border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)

            sev_colours = {
                "critical": (255, 200, 200),
                "high": (255, 230, 200),
                "medium": (255, 255, 200),
                "low": (220, 255, 220),
            }
            for finding in findings[:50]:  # cap at 50 to keep PDF reasonable
                sev = finding.get("severity", "low").lower()
                rc, gc, bc = sev_colours.get(sev, (255, 255, 255))
                pdf.set_fill_color(rc, gc, bc)
                row = [
                    (str(finding.get("type", ""))[:44], 45),
                    (str(finding.get("severity", "")).upper()[:24], 25),
                    (str(finding.get("indicator", ""))[:79], 80),
                    (f"{finding.get('confidence', 0):.0%}"[:24], 25),
                ]
                max_lines = 1
                for text, w in row:
                    n = len(text) // (w // 2) + 1
                    max_lines = max(max_lines, n)
                row_h = max(7, max_lines * 5)
                for text, w in row:
                    pdf.cell(w, row_h, text, border=1, fill=True)
                pdf.ln()

            if len(findings) > 50:
                pdf.set_font("Helvetica", "I", 9)
                pdf.cell(0, 6, f"... and {len(findings) - 50} more findings. See JSON report for full list.",
                         ln=True)
        pdf.ln(3)

        # ── Compliance summary ───────────────────────────────────────────────
        comp = report.get("compliance_summary", {})
        if comp:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 8, "Compliance Impact", ln=True, fill=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, f"GDPR Impact: {comp.get('gdpr_impact', 'N/A').upper()}", ln=True)
            pdf.cell(0, 6, f"HIPAA Impact: {comp.get('hipaa_impact', 'N/A').upper()}", ln=True)
            pdf.cell(0, 6, f"Total Violations: {comp.get('total_violations', 0)}", ln=True)

        # ── Integrity footer ─────────────────────────────────────────────────
        pdf.ln(5)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 5, f"Integrity Hash (findings SHA-256): {report.get('integrity_hash', 'N/A')}", ln=True)

        return bytes(pdf.output())

    except ImportError:
        logger.warning("fpdf2 not available; generating plain-text fallback")
        return _text_fallback(report)
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        return _text_fallback(report)


def _text_fallback(report: Dict) -> bytes:
    """Plain-text report fallback when fpdf2 is unavailable."""
    lines = [
        "Shadow AI Hunter — Security Report",
        "=" * 60,
        f"Report ID: {report.get('report_id')}",
        f"Generated: {report.get('generated_at')}",
        "",
        "Summary",
        "-" * 40,
    ]
    for k, v in report.get("summary", {}).items():
        lines.append(f"  {k}: {v}")
    lines += ["", "Recommendations", "-" * 40]
    for i, r in enumerate(report.get("recommendations", []), 1):
        lines.append(f"  {i}. {r}")
    lines += ["", "Findings", "-" * 40]
    for f in report.get("findings", []):
        lines.append(
            f"  [{f.get('severity', 'N/A').upper()}] {f.get('type')} — {f.get('indicator')}"
        )
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def create_report(scan_id: str, scan_data: Dict, findings: List[Dict], format: str = "json") -> Dict:
    """Main report generation worker function."""
    logger.info(f"[{scan_id}] Generating {format} report ({len(findings)} findings)")

    report = generate_json_report(scan_id, scan_data, findings)

    if format == "json":
        return {
            "scan_id": scan_id,
            "format": "json",
            "content": report,
            "report_id": report["report_id"],
        }
    elif format == "pdf":
        pdf_bytes = generate_pdf_content(report)
        return {
            "scan_id": scan_id,
            "format": "pdf",
            "content": None,  # binary — caller must handle separately
            "pdf_bytes": pdf_bytes,
            "report_id": report["report_id"],
            "size_bytes": len(pdf_bytes),
        }
    else:
        raise ValueError(f"Unsupported report format: {format!r}. Use 'json' or 'pdf'.")


def export_siem(report_payload: Dict) -> Dict:
    """Send report payload to SIEM webhook with retries handled by RQ."""
    url = os.getenv("SIEM_WEBHOOK_URL")
    if not url:
        return {"status": "skipped", "reason": "SIEM_WEBHOOK_URL not set"}
    try:
        resp = requests.post(url, json=report_payload, timeout=10)
        if resp.status_code >= 400:
            raise RuntimeError(f"SIEM webhook failed: {resp.status_code}")
        try:
            client, db = get_db()
            db.siem_deliveries.insert_one({
                "status": "delivered",
                "scan_id": report_payload.get("scan_id"),
                "report_id": report_payload.get("report_id"),
                "detail": {"status_code": resp.status_code},
                "timestamp": now_utc(),
            })
            client.close()
        except Exception:
            pass
        return {"status": "delivered"}
    except Exception as e:
        logger.error(f"SIEM export failed: {e}")
        try:
            client, db = get_db()
            db.siem_deliveries.insert_one({
                "status": "failed",
                "scan_id": report_payload.get("scan_id"),
                "report_id": report_payload.get("report_id"),
                "detail": {"error": str(e)},
                "timestamp": now_utc(),
            })
            client.close()
        except Exception:
            pass
        raise
