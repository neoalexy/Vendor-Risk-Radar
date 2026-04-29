import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "vrr.db"

def get_connection():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            first_seen TEXT NOT NULL,
            last_scanned TEXT
        );

        CREATE TABLE IF NOT EXISTS cve_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            attack_category TEXT,
            is_kev INTEGER DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            FOREIGN KEY (vendor_id) REFERENCES vendors(id)
        );

        CREATE TABLE IF NOT EXISTS risk_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            cve_count INTEGER,
            kev_count INTEGER,
            scanned_at TEXT NOT NULL,
            FOREIGN KEY (vendor_id) REFERENCES vendors(id)
        );
    """)
    
    conn.commit()
    conn.close()

def upsert_vendor(name):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    
    cursor.execute("""
        INSERT INTO vendors (name, first_seen, last_scanned)
        VALUES (?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET last_scanned = excluded.last_scanned
    """, (name, now, now))
    
    conn.commit()
    vendor_id = cursor.execute("SELECT id FROM vendors WHERE name = ?", (name,)).fetchone()["id"]
    conn.close()
    return vendor_id

def save_cves(vendor_id, cves, kev_ids):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    
    for cve in cves:
        is_kev = 1 if cve["id"] in kev_ids else 0
        existing = cursor.execute(
            "SELECT id FROM cve_snapshots WHERE vendor_id = ? AND cve_id = ?",
            (vendor_id, cve["id"])
        ).fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE cve_snapshots SET last_seen = ?, is_kev = ?
                WHERE vendor_id = ? AND cve_id = ?
            """, (now, is_kev, vendor_id, cve["id"]))
        else:
            cursor.execute("""
                INSERT INTO cve_snapshots 
                (vendor_id, cve_id, cvss_score, description, attack_category, is_kev, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (vendor_id, cve["id"], cve["score"], cve["description"], 
                  cve.get("attack_category", "unknown"), is_kev, now, now))
    
    conn.commit()
    conn.close()

def save_risk_score(vendor_id, score, cve_count, kev_count):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.utcnow().isoformat()
    
    cursor.execute("""
        INSERT INTO risk_scores (vendor_id, score, cve_count, kev_count, scanned_at)
        VALUES (?, ?, ?, ?, ?)
    """, (vendor_id, score, cve_count, kev_count, now))
    
    conn.commit()
    conn.close()

def get_previous_cves(vendor_id):
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute(
        "SELECT cve_id FROM cve_snapshots WHERE vendor_id = ?", (vendor_id,)
    ).fetchall()
    conn.close()
    return set(row["cve_id"] for row in rows)

def get_score_history(vendor_name):
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT rs.score, rs.cve_count, rs.kev_count, rs.scanned_at
        FROM risk_scores rs
        JOIN vendors v ON v.id = rs.vendor_id
        WHERE v.name = ?
        ORDER BY rs.scanned_at DESC
        LIMIT 10
    """, (vendor_name,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]