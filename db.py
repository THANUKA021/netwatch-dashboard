"""
db.py — Database and CSV Helper Module
=======================================
All SQLite read/write operations live here.
Keeping database logic separate from app.py makes
the code easier to understand and maintain.

SQLite is a file-based database — no server needed.
The database is stored as a single file: netwatch.db
"""

import csv
import sqlite3
import os
import logging
from datetime import datetime

# Path to the CSV file where we ALSO save every packet
CSV_PATH = os.path.join(os.path.dirname(__file__), "packets.csv")
CSV_HEADERS = ["id", "timestamp", "src_ip", "dst_ip", "protocol", "size", "info"]

# Write CSV header if file is new
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()


# ══════════════════════════════════════════════════════════════════════════════
# INITIALISE DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def init_db(db_path):
    """
    Create the 'packets' table if it doesn't already exist.
    SQLite will create the .db file automatically on first run.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,   -- when the packet was seen (UTC)
            src_ip    TEXT    NOT NULL,   -- who sent the packet
            dst_ip    TEXT    NOT NULL,   -- who is receiving it
            protocol  TEXT    NOT NULL,   -- TCP / UDP / DNS / HTTP / etc.
            size      INTEGER NOT NULL,   -- packet size in bytes
            info      TEXT    DEFAULT ""  -- optional extra detail
        )
    """)
    # Index on timestamp makes time-range queries much faster
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)
    """)
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# INSERT A PACKET
# ══════════════════════════════════════════════════════════════════════════════

def insert_packet(db_path, record):
    """
    Save one packet to:
      1. SQLite database (for querying and analysis)
      2. CSV file (for easy Excel/spreadsheet access)

    'record' is a dict with keys: timestamp, src_ip, dst_ip, protocol, size, info
    """
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, size, info)
            VALUES (:timestamp, :src_ip, :dst_ip, :protocol, :size, :info)
        """, record)
        conn.commit()

        # Also append to CSV
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writerow({
                "id":        cur.lastrowid,
                "timestamp": record["timestamp"],
                "src_ip":    record["src_ip"],
                "dst_ip":    record["dst_ip"],
                "protocol":  record["protocol"],
                "size":      record["size"],
                "info":      record.get("info", ""),
            })

        conn.close()
    except Exception as e:
        logging.error("DB insert failed: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# QUERY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _connect(db_path):
    """Open a SQLite connection that returns rows as dictionaries."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    return conn


def query_packets(db_path, since, protocol=None, device=None, limit=10000):
    """
    Fetch raw packet rows for the given time window.
    Used by the CSV download endpoint.
    """
    conn   = _connect(db_path)
    cur    = conn.cursor()
    params = [since.strftime("%Y-%m-%d %H:%M:%S")]
    sql    = "SELECT * FROM packets WHERE timestamp >= ?"

    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol)
    if device:
        sql += " AND (src_ip = ? OR dst_ip = ?)"
        params.extend([device, device])

    sql += f" ORDER BY id DESC LIMIT {int(limit)}"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_protocol_summary(db_path, since):
    """
    Aggregate traffic by protocol.
    Returns: [{protocol, count, total_bytes}, …]
    """
    conn = _connect(db_path)
    cur  = conn.cursor()
    cur.execute("""
        SELECT protocol,
               COUNT(*)    AS count,
               SUM(size)   AS total_bytes
        FROM packets
        WHERE timestamp >= ?
        GROUP BY protocol
        ORDER BY total_bytes DESC
    """, (since.strftime("%Y-%m-%d %H:%M:%S"),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_device_summary(db_path, since, protocol=None):
    """
    Aggregate traffic per SOURCE IP (device).
    Returns: [{ip, count, total_bytes}, …]
    """
    conn   = _connect(db_path)
    cur    = conn.cursor()
    params = [since.strftime("%Y-%m-%d %H:%M:%S")]
    sql    = """
        SELECT src_ip AS ip,
               COUNT(*)    AS count,
               SUM(size)   AS total_bytes
        FROM packets
        WHERE timestamp >= ?
    """
    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol)

    sql += " GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 20"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_bandwidth_over_time(db_path, since, bucket_minutes=1,
                             protocol=None, device=None):
    """
    Group total bytes transferred into time buckets.
    Returns: [{bucket, total_bytes}, …]

    SQLite's strftime is used to round timestamps to the nearest bucket.
    For example, with bucket_minutes=5 it groups 14:00–14:04 together.
    """
    conn   = _connect(db_path)
    cur    = conn.cursor()
    params = [since.strftime("%Y-%m-%d %H:%M:%S")]

    # SQLite trick: integer-divide minutes to create buckets
    # e.g. for 5-minute buckets: floor(minute / 5) * 5
    if bucket_minutes == 1:
        time_fmt = "%H:%M"
        group_expr = "strftime('%H:%M', timestamp)"
    else:
        # Round down to nearest bucket
        group_expr = (
            f"strftime('%H:', timestamp) || "
            f"printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / {bucket_minutes}) * {bucket_minutes})"
        )
        time_fmt = "%H:%M"

    sql = f"""
        SELECT {group_expr} AS bucket,
               SUM(size)    AS total_bytes
        FROM packets
        WHERE timestamp >= ?
    """
    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol)
    if device:
        sql += " AND (src_ip = ? OR dst_ip = ?)"
        params.extend([device, device])

    sql += " GROUP BY bucket ORDER BY bucket"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_latest_packets(db_path, since, limit=50, protocol=None, device=None):
    """
    Fetch the most recent N packets, newest first.
    """
    conn   = _connect(db_path)
    cur    = conn.cursor()
    params = [since.strftime("%Y-%m-%d %H:%M:%S")]
    sql    = "SELECT * FROM packets WHERE timestamp >= ?"

    if protocol:
        sql += " AND protocol = ?"
        params.append(protocol)
    if device:
        sql += " AND (src_ip = ? OR dst_ip = ?)"
        params.extend([device, device])

    sql += f" ORDER BY id DESC LIMIT {int(limit)}"
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
