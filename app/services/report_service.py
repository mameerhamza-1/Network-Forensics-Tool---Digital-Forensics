from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


def _json_safe_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    safe = []
    for item in records:
        row = {}
        for key, value in item.items():
            if isinstance(value, (pd.Timestamp, datetime)):
                row[key] = value.isoformat(sep=" ", timespec="seconds")
            elif isinstance(value, (set, frozenset)):
                row[key] = list(value)
            else:
                row[key] = value
        safe.append(row)
    return safe


def _build_provider_tables(threat_intel: Dict[str, Any]) -> Dict[str, Any]:
    vt = (threat_intel or {}).get("virustotal", {}) or {}
    ha = (threat_intel or {}).get("hybrid_analysis", {}) or {}

    def flatten(provider_data: Dict[str, Any], provider_name: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for group in ["ips", "domains", "urls", "hashes"]:
            for item in provider_data.get(group, []) or []:
                status = str(item.get("status", "unknown"))
                malicious = int(item.get("malicious", 0) or 0)
                suspicious = int(item.get("suspicious", 0) or 0)
                score = int(item.get("score", 0) or 0)
                severity_label = "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"
                if status in {"error", "rate_limited", "disabled"}:
                    severity_label = "Info"
                rows.append({
                    "provider": provider_name,
                    "indicator": item.get("indicator", "N/A"),
                    "type": item.get("type", group[:-1]),
                    "status": status,
                    "score": score,
                    "severity": severity_label,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "detection_ratio": item.get("detection_ratio", f"{malicious + suspicious}/{item.get('total_engines', 0) or 0}"),
                    "reputation": item.get("reputation", "N/A"),
                    "details": item.get("error") or item.get("verdict") or item.get("categories") or item.get("classification") or "Lookup completed",
                })
        return rows

    vt_rows = flatten(vt, "VirusTotal")
    ha_rows = flatten(ha, "Hybrid Analysis")
    vt_summary = {
        "queried": len(vt_rows),
        "ok": sum(1 for r in vt_rows if r["status"] == "ok"),
        "malicious": sum(1 for r in vt_rows if int(r.get("malicious", 0) or 0) > 0 or int(r.get("score", 0) or 0) >= 35),
        "errors": sum(1 for r in vt_rows if r["status"] in {"error", "rate_limited", "disabled"}),
        "not_found": sum(1 for r in vt_rows if r["status"] == "not_found"),
    }
    if not vt_rows:
        vt_summary["message"] = "No public IOC was available for VirusTotal lookup, or API enrichment was disabled."
    elif vt_summary["malicious"] == 0 and vt_summary["errors"] == 0:
        vt_summary["message"] = "VirusTotal section loaded successfully. No malicious vendor consensus was found for queried indicators."
    elif vt_summary["errors"] > 0:
        vt_summary["message"] = "VirusTotal section loaded, but one or more lookups returned an API/rate-limit/error status."
    else:
        vt_summary["message"] = "VirusTotal found suspicious or malicious reputation signals."

    return {
        "virustotal_rows": vt_rows,
        "hybrid_analysis_rows": ha_rows,
        "virustotal_summary": vt_summary,
    }


def build_case_context(
    source_name: str,
    events_df: pd.DataFrame,
    attack_results: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    protocol_analysis: Dict[str, Any],
    timeline: List[Dict[str, Any]],
    attacker_profiles: List[Dict[str, Any]],
    suspicious_ranking: List[Dict[str, Any]],
    tor_findings: List[Dict[str, Any]] | None = None,
    tls_findings: List[Dict[str, Any]] | None = None,
    risk_records: List[Dict[str, Any]] | None = None,
    iocs: Dict[str, Any] | None = None,
    threat_intel: Dict[str, Any] | None = None,
    anomaly_findings: List[Dict[str, Any]] | None = None,
    rule_findings: List[Dict[str, Any]] | None = None,
    mitre_mappings: List[Dict[str, Any]] | None = None,
    threat_map: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    tor_findings  = tor_findings  or []
    tls_findings  = tls_findings  or []
    risk_records  = risk_records  or []
    iocs = iocs or {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": [], "user_agents": [], "suspicious_payloads": [], "summary": {}}
    threat_intel = threat_intel or {"correlated_iocs": [], "overall_threat_score": 0, "overall_severity": "Low", "confidence_level": "Low", "sophistication_level": "Low", "virustotal": {}, "hybrid_analysis": {}}
    anomaly_findings = anomaly_findings or []
    rule_findings = rule_findings or []
    mitre_mappings = mitre_mappings or []
    threat_map = threat_map or {"points": [], "total_public_ips": 0, "note": "Threat map unavailable."}

    local_top_risk = risk_records[0]["risk_score"] if risk_records else 0
    ti_top_risk = int(threat_intel.get("overall_threat_score", 0) or 0)
    top_risk = max(local_top_risk, ti_top_risk)
    top_label = threat_intel.get("overall_severity") if ti_top_risk > local_top_risk else (risk_records[0]["risk_label"] if risk_records else "Minimal")

    # Build flow graph data: nodes + edges
    flow_nodes = {}
    flow_edges: Dict[tuple, int] = {}
    risk_by_ip = {r["src_ip"]: r for r in risk_records}
    tor_ips    = {f["src_ip"] for f in tor_findings} | {f["dst_ip"] for f in tor_findings}

    for _, row in events_df.iterrows():
        src = str(row["src_ip"])
        dst = str(row["dst_ip"])
        if src not in flow_nodes:
            r = risk_by_ip.get(src, {})
            flow_nodes[src] = {
                "id": src,
                "risk_score": r.get("risk_score", 0),
                "tor": src in tor_ips,
                "label": src,
            }
        if dst not in flow_nodes:
            r = risk_by_ip.get(dst, {})
            flow_nodes[dst] = {
                "id": dst,
                "risk_score": r.get("risk_score", 0),
                "tor": dst in tor_ips,
                "label": dst,
            }
        key = (src, dst)
        flow_edges[key] = flow_edges.get(key, 0) + 1

    # Cap nodes/edges for rendering performance
    sorted_nodes = sorted(flow_nodes.values(), key=lambda n: n["risk_score"], reverse=True)[:30]
    node_ids = {n["id"] for n in sorted_nodes}
    sorted_edges = [
        {"source": s, "target": t, "weight": w}
        for (s, t), w in sorted(flow_edges.items(), key=lambda x: x[1], reverse=True)
        if s in node_ids and t in node_ids
    ][:60]

    provider_tables = _build_provider_tables(threat_intel)

    return {
        "source_name":    source_name,
        "generated_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_events":        int(len(events_df)),
            "total_detections":    int(len(attack_results)),
            "total_sessions":      int(len(sessions)),
            "total_attackers":     int(len(attacker_profiles)),
            "credential_exposures": int(len(protocol_analysis.get("credential_hits", []))),
            "tor_findings":        int(len(tor_findings)),
            "tls_anomalies":       int(sum(1 for f in tls_findings if f.get("classification") != "Normal")),
            "ioc_count":           int(sum(iocs.get("summary", {}).get(k, 0) for k in ["ip_count", "domain_count", "url_count", "hash_count"])),
            "ti_confirmed_iocs":   int(len(threat_intel.get("correlated_iocs", []))),
            "behavior_anomalies":   int(len(anomaly_findings)),
            "rule_matches":         int(len(rule_findings)),
            "mitre_techniques":     int(len({m.get("technique_id") for m in mitre_mappings})),
            "overall_risk_score":  top_risk,
            "overall_risk_label":  top_label,
        },
        "attacks":          _json_safe_records(attack_results),
        "sessions":         _json_safe_records(sessions[:50]),
        "protocol_analysis": {
            **protocol_analysis,
            "credential_hits": _json_safe_records(protocol_analysis.get("credential_hits", [])),
        },
        "timeline":          _json_safe_records(timeline[:200]),
        "attacker_profiles": _json_safe_records(attacker_profiles),
        "suspicious_ranking": _json_safe_records(suspicious_ranking),
        "tor_findings":      _json_safe_records(tor_findings),
        "tls_findings":      _json_safe_records(tls_findings[:50]),
        "risk_records":      _json_safe_records(risk_records[:20]),
        "iocs": {
            **iocs,
            "suspicious_payloads": _json_safe_records(iocs.get("suspicious_payloads", [])),
        },
        "threat_intel": {
            **threat_intel,
            "correlated_iocs": _json_safe_records(threat_intel.get("correlated_iocs", [])),
        },
        "virustotal_rows": _json_safe_records(provider_tables.get("virustotal_rows", [])),
        "hybrid_analysis_rows": _json_safe_records(provider_tables.get("hybrid_analysis_rows", [])),
        "virustotal_summary": provider_tables.get("virustotal_summary", {}),
        "anomaly_findings": _json_safe_records(anomaly_findings),
        "rule_findings": _json_safe_records(rule_findings),
        "mitre_mappings": _json_safe_records(mitre_mappings),
        "threat_map": threat_map,
        "flow_graph": {
            "nodes": sorted_nodes,
            "edges": sorted_edges,
        },
        "charts": {
            "protocol_labels": [i["protocol"] for i in protocol_analysis.get("protocol_counts", [])],
            "protocol_values": [i["count"] for i in protocol_analysis.get("protocol_counts", [])],
            "port_labels":     [str(i.get("dst_port", i.get("port", ""))) for i in protocol_analysis.get("top_ports", [])],
            "port_values":     [i["count"] for i in protocol_analysis.get("top_ports", [])],
            "talker_labels":   [i["src_ip"] for i in protocol_analysis.get("top_talkers", [])],
            "talker_values":   [i["count"] for i in protocol_analysis.get("top_talkers", [])],
            "risk_labels":     [i["src_ip"] for i in suspicious_ranking[:10]],
            "risk_values":     [i["risk_score"] for i in suspicious_ranking[:10]],
        },
    }


def generate_pdf_report(app, context: Dict[str, Any]) -> str:
    reports_dir = Path(app.config["REPORT_FOLDER"])
    reports_dir.mkdir(parents=True, exist_ok=True)
    filename = reports_dir / f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except Exception as exc:
        raise RuntimeError("PDF export requires reportlab.") from exc

    styles = getSampleStyleSheet()
    small   = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, leading=10)
    title   = styles["Title"]
    heading = styles["Heading2"]
    normal  = styles["BodyText"]

    doc = SimpleDocTemplate(str(filename), pagesize=A4,
                            leftMargin=14*mm, rightMargin=14*mm,
                            topMargin=14*mm, bottomMargin=14*mm)
    story = []
    story.append(Paragraph("Network Forensic Report", title))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Source: {context.get('source_name','N/A')}", normal))
    story.append(Paragraph(f"Generated At: {context.get('generated_at','N/A')}", normal))
    story.append(Spacer(1, 10))

    summary = context.get("summary", {})
    summary_rows = [["Metric","Value"]] + [[k.replace("_"," ").title(), str(v)] for k,v in summary.items()]
    t = Table(summary_rows, repeatRows=1, colWidths=[70*mm, 90*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dbeafe")),
        ("GRID",(0,0),(-1,-1),0.4,colors.grey),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))
    story.append(t); story.append(Spacer(1, 12))

    threat_intel = context.get("threat_intel", {})
    correlated = threat_intel.get("correlated_iocs", [])[:15]
    if threat_intel:
        story.append(Paragraph("Threat Intelligence Summary", heading))
        ti_rows = [["Metric", "Value"],
                   ["Overall Threat Score", str(threat_intel.get("overall_threat_score", 0))],
                   ["Severity", str(threat_intel.get("overall_severity", "Low"))],
                   ["Confidence", str(threat_intel.get("confidence_level", "Low"))],
                   ["Sophistication", str(threat_intel.get("sophistication_level", "Low"))]]
        t = Table(ti_rows, repeatRows=1, colWidths=[70*mm, 90*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#cffafe")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))
    # Always-visible VirusTotal section, even when results are clean, empty, disabled, or rate-limited.
    vt_summary = context.get("virustotal_summary", {}) or {}
    vt_rows = context.get("virustotal_rows", [])[:25]
    story.append(Paragraph("VirusTotal Findings", heading))
    vt_info_rows = [["Metric", "Value"],
                    ["Status Message", str(vt_summary.get("message", "VirusTotal section loaded."))],
                    ["Total Queried IOCs", str(vt_summary.get("queried", 0))],
                    ["Successful Lookups", str(vt_summary.get("ok", 0))],
                    ["Malicious/Suspicious Matches", str(vt_summary.get("malicious", 0))],
                    ["Not Found", str(vt_summary.get("not_found", 0))],
                    ["Errors/Rate Limits", str(vt_summary.get("errors", 0))]]
    t = Table(vt_info_rows, repeatRows=1, colWidths=[55*mm, 105*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#ede9fe")),
        ("GRID",(0,0),(-1,-1),0.4,colors.grey),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))
    story.append(t); story.append(Spacer(1, 8))
    vt_table_rows = [["Indicator", "Type", "Status", "Ratio", "Score"]]
    if vt_rows:
        for item in vt_rows:
            vt_table_rows.append([
                Paragraph(str(item.get("indicator", "N/A"))[:55], small),
                Paragraph(str(item.get("type", "ioc")), small),
                Paragraph(str(item.get("status", "unknown")), small),
                Paragraph(str(item.get("detection_ratio", "0/0")), small),
                Paragraph(str(item.get("score", 0)), small),
            ])
    else:
        vt_table_rows.append([Paragraph("No public IP/domain/URL/hash available for VirusTotal lookup.", small), "-", "no_ioc", "0/0", "0"])
    t = Table(vt_table_rows, repeatRows=1, colWidths=[70*mm,25*mm,30*mm,25*mm,20*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dbeafe")),
        ("GRID",(0,0),(-1,-1),0.4,colors.grey),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))
    story.append(t); story.append(Spacer(1, 12))

    if correlated:
        story.append(Paragraph("Correlated IOCs", heading))
        rows = [["Indicator", "Type", "Providers", "Score", "Severity"]]
        for item in correlated:
            rows.append([
                Paragraph(str(item.get("indicator", "N/A"))[:60], small),
                Paragraph(str(item.get("type", "ioc")), small),
                Paragraph(", ".join(item.get("providers", [])), small),
                Paragraph(str(item.get("score", 0)), small),
                Paragraph(str(item.get("severity", "Low")), small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[65*mm,22*mm,40*mm,18*mm,25*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#fee2e2")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))

    # Tor section
    tor = context.get("tor_findings", [])[:10]
    if tor:
        story.append(Paragraph("Tor Traffic Detections", heading))
        rows = [["Source IP","Destination IP","Confidence","Reason"]]
        for item in tor:
            rows.append([
                Paragraph(str(item.get("src_ip","N/A")), small),
                Paragraph(str(item.get("dst_ip","N/A")), small),
                Paragraph(str(item.get("confidence","N/A")), small),
                Paragraph(str(item.get("reason","N/A")), small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[35*mm,35*mm,20*mm,80*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#ede9fe")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))

    # MITRE ATT&CK mapping section
    mitre_rows = context.get("mitre_mappings", [])[:25]
    if mitre_rows:
        story.append(Paragraph("MITRE ATT&CK Mapping", heading))
        rows = [["Attack", "Tactic", "Technique", "Source", "Recommendation"]]
        for item in mitre_rows:
            rows.append([
                Paragraph(str(item.get("attack_type", "N/A"))[:35], small),
                Paragraph(str(item.get("tactic", "N/A")), small),
                Paragraph(f"{item.get('technique_id','')} {item.get('technique','')}", small),
                Paragraph(str(item.get("src_ip", "N/A")), small),
                Paragraph(str(item.get("recommendation", "N/A"))[:90], small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[34*mm,28*mm,42*mm,28*mm,38*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#ffedd5")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))

    # Behavior anomaly and rule-match sections
    anomaly_rows = context.get("anomaly_findings", [])[:15]
    if anomaly_rows:
        story.append(Paragraph("Behavior Anomaly Findings", heading))
        rows = [["Source IP", "Score", "Severity", "Reason"]]
        for item in anomaly_rows:
            rows.append([Paragraph(str(item.get("src_ip","N/A")), small), Paragraph(str(item.get("score",0)), small), Paragraph(str(item.get("severity","N/A")), small), Paragraph(str(item.get("reason","N/A")), small)])
        t = Table(rows, repeatRows=1, colWidths=[45*mm,20*mm,25*mm,80*mm])
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#cffafe")),("GRID",(0,0),(-1,-1),0.4,colors.grey),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(t); story.append(Spacer(1, 12))

    rule_rows = context.get("rule_findings", [])[:15]
    if rule_rows:
        story.append(Paragraph("YARA/Sigma-Style Rule Matches", heading))
        rows = [["Rule", "Type", "Severity", "Source", "Evidence"]]
        for item in rule_rows:
            rows.append([Paragraph(str(item.get("rule_name","N/A"))[:35], small), Paragraph(str(item.get("rule_type","N/A")), small), Paragraph(str(item.get("severity","N/A")), small), Paragraph(str(item.get("src_ip","N/A")), small), Paragraph(str(item.get("evidence",""))[:80], small)])
        t = Table(rows, repeatRows=1, colWidths=[45*mm,18*mm,22*mm,32*mm,53*mm])
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#fee2e2")),("GRID",(0,0),(-1,-1),0.4,colors.grey),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(t); story.append(Spacer(1, 12))

    attacks = context.get("attacks", [])[:20]
    if attacks:
        story.append(Paragraph("Detected Attacks", heading))
        rows = [["Attack","Source","Destination","Risk","Evidence"]]
        for item in attacks:
            rows.append([
                Paragraph(str(item.get("attack_type","N/A")), small),
                Paragraph(str(item.get("src_ip","N/A")), small),
                Paragraph(str(item.get("dst_ip","N/A")), small),
                Paragraph(str(item.get("risk_score","N/A")), small),
                Paragraph(str(item.get("evidence",""))[:80], small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[45*mm,32*mm,32*mm,15*mm,46*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e2e8f0")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))

    ranked = context.get("suspicious_ranking", [])[:15]
    if ranked:
        story.append(Paragraph("Top Suspicious IPs", heading))
        rows = [["IP","Risk","Label","Events","Sessions"]]
        for item in ranked:
            rows.append([
                Paragraph(str(item.get("src_ip","N/A")), small),
                Paragraph(str(item.get("risk_score","N/A")), small),
                Paragraph(str(item.get("risk_label","N/A")), small),
                Paragraph(str(item.get("event_count","N/A")), small),
                Paragraph(str(item.get("session_count","N/A")), small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[55*mm,20*mm,25*mm,25*mm,25*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e2e8f0")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t); story.append(Spacer(1, 12))

    creds = context.get("protocol_analysis", {}).get("credential_hits", [])[:15]
    if creds:
        story.append(Paragraph("Credential Exposure Findings", heading))
        rows = [["Source","Destination","Preview"]]
        for item in creds:
            rows.append([
                Paragraph(str(item.get("src_ip","N/A")), small),
                Paragraph(str(item.get("dst_ip","N/A")), small),
                Paragraph(str(item.get("payload_excerpt","N/A")), small),
            ])
        t = Table(rows, repeatRows=1, colWidths=[35*mm,35*mm,100*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e2e8f0")),
            ("GRID",(0,0),(-1,-1),0.4,colors.grey),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
        ]))
        story.append(t)

    doc.build(story)
    return str(filename)
