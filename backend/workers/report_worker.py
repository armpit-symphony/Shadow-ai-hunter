"""
Report Worker for Shadow AI Hunter
Generates JSON and PDF reports
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
import json
import hashlib

logger = logging.getLogger(__name__)


def generate_json_report(scan_id: str, scan_data: Dict, findings: List[Dict]) -> Dict:
    """Generate JSON report"""
    
    report = {
        "report_id": f"report-{scan_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "scan_id": scan_id,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_events": scan_data.get("events_processed", 0),
            "findings_count": len(findings),
            "risk_level": calculate_risk_level(findings)
        },
        "findings": findings,
        "scan_details": scan_data,
        "compliance_summary": generate_compliance_summary(findings),
        "recommendations": generate_recommendations(findings)
    }
    
    # Add hash for integrity
    report["hash"] = hashlib.sha256(
        json.dumps(report, sort_keys=True).encode()
    ).hexdigest()
    
    return report


def generate_pdf_content(report: Dict) -> bytes:
    """
    Generate PDF report content
    Note: This is a placeholder. Production would use a PDF library.
    """
    # TODO: Implement actual PDF generation with reportlab or fpdf2
    content = f"""
    Shadow AI Hunter - Security Report
    ==================================
    
    Report ID: {report.get('report_id')}
    Generated: {report.get('generated_at')}
    
    Summary
    -------
    Total Events: {report['summary']['total_events']}
    Findings: {report['summary']['findings_count']}
    Risk Level: {report['summary']['risk_level']}
    
    Findings
    --------
    """
    
    for i, finding in enumerate(report.get('findings', []), 1):
        content += f"\n{i}. {finding.get('type')} - {finding.get('severity')}\n"
        content += f"   Indicator: {finding.get('indicator')}\n"
        content += f"   Confidence: {finding.get('confidence', 'N/A')}\n"
    
    return content.encode('utf-8')


def calculate_risk_level(findings: List[Dict]) -> str:
    """Calculate overall risk level"""
    if not findings:
        return "low"
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    if severity_counts["critical"] > 0:
        return "critical"
    elif severity_counts["high"] > 0:
        return "high"
    elif severity_counts["medium"] > 0:
        return "medium"
    return "low"


def generate_compliance_summary(findings: List[Dict]) -> Dict:
    """Generate compliance-focused summary"""
    categories = {}
    for f in findings:
        cat = f.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
    
    return {
        "categories": categories,
        "gdpr_impact": "high" if categories.get("llm", 0) > 0 else "low",
        "hipaa_impact": "medium" if categories.get("healthcare", 0) > 0 else "low",
        "total_violations": len(findings)
    }


def generate_recommendations(findings: List[Dict]) -> List[str]:
    """Generate recommendations based on findings"""
    recommendations = []
    
    # Group by type
    ai_services = [f for f in findings if f.get("type", "").startswith("ai_")]
    if ai_services:
        recommendations.append(
            f"Review {len(ai_services)} unauthorized AI service accesses. "
            "Consider blocking at DNS/proxy level."
        )
    
    high_volume = [f for f in findings if f.get("type") == "high_volume_upload"]
    if high_volume:
        recommendations.append(
            "Investigate high-volume data uploads to external AI services. "
            "Review data loss prevention policies."
        )
    
    new_destinations = [f for f in findings if f.get("type") == "new_ai_destination"]
    if new_destinations:
        recommendations.append(
            f"Monitor {len(new_destinations)} new AI service destinations. "
            "Update allowlist/blocklist as needed."
        )
    
    if not recommendations:
        recommendations.append("Continue monitoring. No critical issues detected.")
    
    return recommendations


def create_report(scan_id: str, scan_data: Dict, findings: List[Dict], format: str = "json") -> Dict:
    """Main report generation worker"""
    logger.info(f"[{scan_id}] Generating {format} report")
    
    if format == "json":
        report = generate_json_report(scan_id, scan_data, findings)
        return {
            "scan_id": scan_id,
            "format": "json",
            "content": report,
            "report_id": report["report_id"]
        }
    elif format == "pdf":
        report = generate_json_report(scan_id, scan_data, findings)
        pdf_content = generate_pdf_content(report)
        return {
            "scan_id": scan_id,
            "format": "pdf",
            "content": pdf_content,
            "report_id": report["report_id"]
        }
    else:
        raise ValueError(f"Unsupported format: {format}")
