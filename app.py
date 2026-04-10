"""
NetWatch - Network Traffic Monitoring and Analysis Dashboard
============================================================
Main Flask application file.
This is the "brain" of the project — it:
  1. Starts a background thread that captures live network packets
  2. Stores packet data in SQLite (a file-based database) and CSV
  3. Serves a web dashboard with charts and tables
  4. Provides REST API endpoints so the dashboard can auto-refresh
  5. Handles anomaly detection and report downloads

Run with:  sudo python app.py
(sudo is needed on Linux/macOS to capture raw network packets)
"""

import os
import csv
import time
import json
import sqlite3
import logging
import threading
import statistics
from datetime import datetime, timedelta
from io import StringIO, BytesIO

from flask import Flask, render_template, jsonify, request, send_file, Response
import pandas as pd

# ── import our own helper modules ──────────────────────────────────────────────
from capture import start_capture, get_packet_buffer
from db import init_db, insert_packet, query_packets, get_protocol_summary, \
               get_device_summary, get_bandwidth_over_time, get_latest_packets

# ── optional: PDF report generation ───────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logging.warning("reportlab not installed — PDF export will be unavailable.")

# ── Flask app setup ────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Path to the SQLite database file
DB_PATH = os.path.join(os.path.dirname(__file__), "netwatch.db")

# Anomaly threshold: devices whose traffic (bytes) exceeds
#   mean + ANOMALY_SIGMA * std-deviation are flagged
ANOMALY_SIGMA = 2.0


# ══════════════════════════════════════════════════════════════════════════════
# HELPER: Detect anomalous devices
# ══════════════════════════════════════════════════════════════════════════════
def detect_anomalies(device_rows):
    """
    Given a list of (ip, total_bytes) rows, return a set of IPs
    whose traffic is unusually high compared to the rest.
    Uses a simple z-score approach: flag if > mean + 2*std.
    """
    if len(device_rows) < 3:
        return set()   # need at least 3 devices to compare

    traffic = [row["total_bytes"] for row in device_rows]
    mean = statistics.mean(traffic)
    std  = statistics.stdev(traffic)

    if std == 0:
        return set()   # all devices the same — nothing to flag

    flagged = set()
    for row in device_rows:
        z = (row["total_bytes"] - mean) / std
        if z > ANOMALY_SIGMA:
            flagged.add(row["ip"])
    return flagged


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE: Main dashboard page
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    """Serve the main HTML dashboard page."""
    return render_template("index.html", pdf_available=PDF_AVAILABLE)


# ══════════════════════════════════════════════════════════════════════════════
# API: Protocol summary  →  used for the bar chart
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/protocols")
def api_protocols():
    """
    Returns JSON: list of {protocol, count, total_bytes}
    Supports optional ?hours=N filter (default last 1 hour).
    """
    hours  = request.args.get("hours", 1, type=float)
    since  = datetime.utcnow() - timedelta(hours=hours)
    rows   = get_protocol_summary(DB_PATH, since)
    return jsonify(rows)


# ══════════════════════════════════════════════════════════════════════════════
# API: Device summary  →  used for the pie chart + anomaly detection
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/devices")
def api_devices():
    """
    Returns JSON: list of {ip, count, total_bytes}
    Also adds an 'anomaly' boolean for each device.
    """
    hours  = request.args.get("hours", 1, type=float)
    proto  = request.args.get("protocol", None)
    since  = datetime.utcnow() - timedelta(hours=hours)
    rows   = get_device_summary(DB_PATH, since, protocol=proto)

    anomalous = detect_anomalies(rows)
    for row in rows:
        row["anomaly"] = row["ip"] in anomalous

    return jsonify(rows)


# ══════════════════════════════════════════════════════════════════════════════
# API: Bandwidth over time  →  used for the line chart
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/bandwidth")
def api_bandwidth():
    """
    Returns JSON: list of {bucket, total_bytes}
    'bucket' is a time label (e.g. "14:05").
    Resolution adjusts to the requested window so the chart stays readable.
    """
    hours    = request.args.get("hours", 1, type=float)
    proto    = request.args.get("protocol", None)
    device   = request.args.get("device", None)
    since    = datetime.utcnow() - timedelta(hours=hours)

    # Choose bucket size based on window
    if hours <= 1:
        bucket_minutes = 1
    elif hours <= 6:
        bucket_minutes = 5
    else:
        bucket_minutes = 15

    rows = get_bandwidth_over_time(DB_PATH, since, bucket_minutes,
                                   protocol=proto, device=device)
    return jsonify(rows)


# ══════════════════════════════════════════════════════════════════════════════
# API: Latest packets table
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/packets")
def api_packets():
    """
    Returns JSON: last N packets with all fields.
    Supports ?limit=N, ?protocol=X, ?device=Y, ?hours=H filters.
    """
    limit    = request.args.get("limit",    50,   type=int)
    protocol = request.args.get("protocol", None)
    device   = request.args.get("device",   None)
    hours    = request.args.get("hours",    1,    type=float)
    since    = datetime.utcnow() - timedelta(hours=hours)

    rows = get_latest_packets(DB_PATH, since, limit=limit,
                              protocol=protocol, device=device)
    return jsonify(rows)


# ══════════════════════════════════════════════════════════════════════════════
# API: Stats summary card values
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/stats")
def api_stats():
    """
    Returns high-level numbers shown in the summary cards at the top:
      - total packets captured
      - total data transferred (MB)
      - number of unique devices
      - most active protocol
    """
    hours = request.args.get("hours", 1, type=float)
    since = datetime.utcnow() - timedelta(hours=hours)

    conn  = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur   = conn.cursor()

    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        SELECT COUNT(*) as total_packets,
               COALESCE(SUM(size), 0) as total_bytes
        FROM packets WHERE timestamp >= ?
    """, (since_str,))
    row = cur.fetchone()

    cur.execute("""
        SELECT COUNT(DISTINCT src_ip) + COUNT(DISTINCT dst_ip) as unique_ips
        FROM packets WHERE timestamp >= ?
    """, (since_str,))
    ip_row = cur.fetchone()

    cur.execute("""
        SELECT protocol, COUNT(*) as cnt
        FROM packets WHERE timestamp >= ?
        GROUP BY protocol ORDER BY cnt DESC LIMIT 1
    """, (since_str,))
    proto_row = cur.fetchone()

    conn.close()

    return jsonify({
        "total_packets":  row["total_packets"],
        "total_mb":       round(row["total_bytes"] / 1_048_576, 2),
        "unique_devices": ip_row["unique_ips"] if ip_row else 0,
        "top_protocol":   proto_row["protocol"] if proto_row else "—",
    })


# ══════════════════════════════════════════════════════════════════════════════
# DOWNLOAD: CSV report
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/download/csv")
def download_csv():
    """Stream all packets from the last N hours as a downloadable CSV file."""
    hours  = request.args.get("hours", 1, type=float)
    since  = datetime.utcnow() - timedelta(hours=hours)
    rows   = query_packets(DB_PATH, since)

    si = StringIO()
    writer = csv.DictWriter(si, fieldnames=["id","timestamp","src_ip","dst_ip",
                                             "protocol","size","info"])
    writer.writeheader()
    writer.writerows(rows)

    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netwatch_report.csv"}
    )


# ══════════════════════════════════════════════════════════════════════════════
# DOWNLOAD: PDF report
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/download/pdf")
def download_pdf():
    """Generate and download a PDF summary report using ReportLab."""
    if not PDF_AVAILABLE:
        return "PDF export not available. Install reportlab: pip install reportlab", 503

    hours  = request.args.get("hours", 1, type=float)
    since  = datetime.utcnow() - timedelta(hours=hours)
    rows   = get_latest_packets(DB_PATH, since, limit=200)
    protos = get_protocol_summary(DB_PATH, since)
    devs   = get_device_summary(DB_PATH, since)

    buf    = BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story  = []

    # ── Title ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("NetWatch — Network Traffic Report", styles["Title"]))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Window: last {hours} hour(s)", styles["Normal"]))
    story.append(Spacer(1, 16))

    # ── Protocol summary table ─────────────────────────────────────────────────
    story.append(Paragraph("Protocol Summary", styles["Heading2"]))
    p_data = [["Protocol", "Packets", "Total Bytes"]] + \
             [[r["protocol"], r["count"], r["total_bytes"]] for r in protos]
    p_table = Table(p_data, hAlign="LEFT")
    p_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0d6efd")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0f4ff")]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
    ]))
    story.append(p_table)
    story.append(Spacer(1, 12))

    # ── Top devices table ──────────────────────────────────────────────────────
    story.append(Paragraph("Top Devices by Traffic", styles["Heading2"]))
    anomalous = detect_anomalies(devs)
    d_data = [["IP Address", "Packets", "Total Bytes", "Anomaly"]] + \
             [[r["ip"], r["count"], r["total_bytes"], "⚠ YES" if r["ip"] in anomalous else "OK"]
              for r in devs[:20]]
    d_table = Table(d_data, hAlign="LEFT")
    d_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#198754")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f0fff4")]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
    ]))
    story.append(d_table)
    story.append(Spacer(1, 12))

    # ── Recent packets table ───────────────────────────────────────────────────
    story.append(Paragraph("Recent Packets (up to 50)", styles["Heading2"]))
    pk_data = [["Timestamp", "Src IP", "Dst IP", "Protocol", "Size"]] + \
              [[r["timestamp"][:19], r["src_ip"], r["dst_ip"],
                r["protocol"], r["size"]] for r in rows[:50]]
    pk_table = Table(pk_data, hAlign="LEFT", colWidths=[110,100,100,70,60])
    pk_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#6f42c1")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#fdf0ff")]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
    ]))
    story.append(pk_table)

    doc.build(story)
    buf.seek(0)

    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True,
                     download_name="netwatch_report.pdf")


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # 1. Initialise the database (creates tables if they don't exist yet)
    init_db(DB_PATH)
    logging.info("Database initialised at %s", DB_PATH)

    # 2. Start the packet capture in a background daemon thread
    #    (daemon=True means it will stop automatically when Flask exits)
    capture_thread = threading.Thread(
        target=start_capture,
        args=(DB_PATH,),
        daemon=True
    )
    capture_thread.start()
    logging.info("Packet capture thread started.")

    # 3. Launch Flask (debug=False for stability when capturing)
    logging.info("Starting Flask on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
