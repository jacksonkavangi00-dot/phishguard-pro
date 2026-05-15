import sqlite3
from datetime import datetime

DB_PATH = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        risk_score INTEGER,
        threat_level TEXT,
        confidence REAL,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_scan(url, score, level, confidence):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        INSERT INTO scans (url, risk_score, threat_level, confidence, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (url, score, level, confidence, datetime.now().isoformat()))

    conn.commit()
    conn.close()


def get_scans(limit=50):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT url, risk_score, threat_level, confidence, timestamp
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = c.fetchall()
    conn.close()

    return rows
