from __future__ import annotations

import io
import json
import os
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_socketio import SocketIO

from app.core.config import Config
from app.core.utils import save_uploaded_file
from app.services.attack_detection import detect_attacks
from app.services.ingestion import load_input_data
from app.services.ioc_extraction import extract_iocs
from app.services.virustotal_service import VirusTotalService
from app.services.hybrid_analysis_service import HybridAnalysisService
from app.services.threat_intel_db import save_ioc_history
from app.core.threat_correlation import correlate_threats
from app.services.live_monitor import LiveMonitor
from app.services.protocol_analysis import build_protocol_analysis
from app.services.report_service import build_case_context, generate_pdf_report
from app.services.risk import build_attacker_profiles, rank_suspicious_ips, compute_risk_scores
from app.services.session_reconstruction import reconstruct_sessions
from app.services.timeline import build_timeline
from app.services.tor_detection import detect_tor
from app.services.tls_fingerprint import fingerprint_tls
from app.services.mitre_mapping import map_attacks_to_mitre
from app.services.anomaly_detection import detect_behavior_anomalies
from app.services.threat_map import build_threat_map
from app.services.rules_scanner import scan_payload_rules
from app.services.alerting import build_alerts, send_webhook_alert
from app.services.hunting import hunt_context


def create_app() -> tuple[Flask, SocketIO, LiveMonitor]:
    # FIX BUG-12: use absolute paths so app works from any working directory
    _HERE = Path(__file__).parent
    app = Flask(__name__,
                template_folder=str(_HERE / "templates"),
                static_folder=str(_HERE / "static"))
    app.config.from_object(Config)

    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )
    monitor = LiveMonitor(socketio)

    @app.route("/")
    def index():
        return redirect(url_for("upload"))

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "POST":
            uploaded_file = request.files.get("evidence_file")
            source_type   = request.form.get("source_type", "auto")

            if not uploaded_file or uploaded_file.filename == "":
                flash("Please select a PCAP, CSV, TXT, or LOG evidence file.", "warning")
                return redirect(url_for("upload"))

            saved_path = save_uploaded_file(uploaded_file, app.config["UPLOAD_FOLDER"])

            try:
                events_df          = load_input_data(saved_path, source_type)
                attack_results     = detect_attacks(events_df)
                tor_findings       = detect_tor(events_df)
                tls_findings       = fingerprint_tls(events_df)
                sessions           = reconstruct_sessions(events_df)
                protocol_analysis  = build_protocol_analysis(events_df)
                timeline           = build_timeline(events_df, attack_results)
                risk_records       = compute_risk_scores(events_df, attack_results, tor_findings, tls_findings)

                # Hybrid Threat Intelligence Layer
                # Local rules remain the first layer. External APIs enrich extracted IOCs when keys are present.
                iocs = extract_iocs(events_df, saved_path)
                vt_results = {"ips": [], "domains": [], "urls": [], "hashes": []}
                ha_results = {"hashes": [], "submission": {"status": "skipped"}}
                if app.config.get("THREAT_INTEL_ENABLED", True):
                    vt_results = VirusTotalService().enrich_iocs(iocs)
                    ha_results = HybridAnalysisService().enrich_iocs(iocs, saved_path)

                threat_intel = correlate_threats(
                    iocs=iocs,
                    local_attacks=attack_results,
                    risk_records=risk_records,
                    vt_results=vt_results,
                    ha_results=ha_results,
                )

                # Advanced SOC/DFIR enhancement layer
                anomaly_findings = detect_behavior_anomalies(events_df)
                rule_findings = scan_payload_rules(events_df)
                mitre_mappings = map_attacks_to_mitre(attack_results, threat_intel)
                try:
                    save_ioc_history(os.path.basename(saved_path), threat_intel.get("correlated_iocs", []))
                except Exception:
                    pass

                # Raise local source risk when public threat intelligence strongly confirms malicious indicators.
                ti_score = int(threat_intel.get("overall_threat_score", 0) or 0)
                if ti_score >= 60 and risk_records:
                    current_score = int(risk_records[0].get("risk_score", 0))
                    if ti_score > current_score:
                        risk_records[0]["risk_score"] = ti_score
                        risk_records[0]["risk_label"] = threat_intel.get("overall_severity", risk_records[0].get("risk_label", "High"))
                    risk_records[0].setdefault("reasons", []).append("External threat intelligence correlation")

                attacker_profiles  = build_attacker_profiles(events_df, attack_results, sessions, risk_records)
                suspicious_ranking = rank_suspicious_ips(attacker_profiles)

                context = build_case_context(
                    source_name=os.path.basename(saved_path),
                    events_df=events_df,
                    attack_results=attack_results,
                    sessions=sessions,
                    protocol_analysis=protocol_analysis,
                    timeline=timeline,
                    attacker_profiles=attacker_profiles,
                    suspicious_ranking=suspicious_ranking,
                    tor_findings=tor_findings,
                    tls_findings=tls_findings,
                    risk_records=risk_records,
                    iocs=iocs,
                    threat_intel=threat_intel,
                    anomaly_findings=anomaly_findings,
                    rule_findings=rule_findings,
                    mitre_mappings=mitre_mappings,
                    threat_map=build_threat_map(events_df, suspicious_ranking, threat_intel.get("correlated_iocs", [])),
                )
                context["alerts"] = build_alerts(context)

                app.config["LATEST_CONTEXT"] = context
                return render_template("dashboard.html", **context)

            except Exception as exc:
                flash(f"Failed to process evidence: {exc}", "danger")
                return redirect(url_for("upload"))

        return render_template("upload.html")

    @app.route("/dashboard")
    def dashboard():
        context = app.config.get("LATEST_CONTEXT")
        if not context:
            flash("Upload evidence first.", "info")
            return redirect(url_for("upload"))
        return render_template("dashboard.html", **context)

    @app.route("/live")
    def live():
        return render_template("live.html")

    @app.route("/live/start", methods=["POST"])
    def start_live_capture():
        interface    = (request.form.get("interface") or "").strip() or None
        packet_count = int(request.form.get("packet_count", 0) or 0)
        try:
            monitor.start(interface=interface, packet_count=packet_count)
            return jsonify({"status": "ok", "message": "Live capture started."})
        except Exception as exc:
            return jsonify({"status": "error", "message": str(exc)}), 500

    @app.route("/live/stop", methods=["POST"])
    def stop_live_capture():
        try:
            monitor.stop()
            return jsonify({"status": "ok", "message": "Capture stopped."})
        except Exception as exc:
            return jsonify({"status": "error", "message": str(exc)}), 500

    @app.route("/live/status")
    def live_capture_status():
        """Lightweight polling endpoint — returns current capture stats as JSON."""
        return jsonify({
            "running":  monitor.is_running,
            "captured": monitor.captured_count,
        })

    @app.route("/live/download")
    def download_live_csv():
        csv_data = monitor.get_csv()
        lines    = csv_data.strip().splitlines()
        if len(lines) <= 1:
            flash("No packets captured yet. Run a live capture first.", "warning")
            return redirect(url_for("live"))
        buf = io.BytesIO(csv_data.encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="text/csv", as_attachment=True, download_name="live_capture.csv")

    @app.route("/report")
    def report():
        context = app.config.get("LATEST_CONTEXT")
        if not context:
            flash("No case available yet.", "warning")
            return redirect(url_for("upload"))
        return render_template("report.html", **context)

    @app.route("/hunt")
    def hunt():
        context = app.config.get("LATEST_CONTEXT")
        if not context:
            return jsonify({"error": "Upload evidence first."}), 400
        query = request.args.get("q", "")
        return jsonify(hunt_context(context, query))

    @app.route("/alerts/send", methods=["POST"])
    def send_alert():
        context = app.config.get("LATEST_CONTEXT")
        if not context:
            return jsonify({"status": "error", "message": "No case available."}), 400
        alerts = context.get("alerts", [])
        if not alerts:
            return jsonify({"status": "ok", "message": "No critical alerts to send."})
        return jsonify(send_webhook_alert(alerts[0]))

    @app.route("/report/pdf")
    def report_pdf():
        context = app.config.get("LATEST_CONTEXT")
        if not context:
            flash("No case available yet.", "warning")
            return redirect(url_for("upload"))
        try:
            output_path = generate_pdf_report(app, context)
            return send_file(output_path, as_attachment=True)
        except Exception as exc:
            flash(f"PDF export failed: {exc}", "warning")
            return redirect(url_for("report"))

    return app, socketio, monitor


app, socketio, _monitor = create_app()

if __name__ == "__main__":
    Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
    Path(Config.REPORT_FOLDER).mkdir(parents=True, exist_ok=True)
    socketio.run(
        app,
        debug=False,
        host="127.0.0.1",
        port=5000,
        allow_unsafe_werkzeug=True,
    )
