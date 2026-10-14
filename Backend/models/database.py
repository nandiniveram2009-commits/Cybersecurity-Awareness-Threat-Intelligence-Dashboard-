import sqlite3
import os

DB_PATH = "data/cybersecurity.db"

def get_db_connection():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        threat_name TEXT,
        category TEXT,
        description TEXT,
        severity TEXT,
        risk_score INTEGER,
        confidence_score INTEGER,
        status TEXT,
        first_seen TEXT,
        last_seen TEXT,
        indicator_type TEXT,
        indicator_value TEXT,
        source_name TEXT,
        source_reliability TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        cve_id TEXT
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        threat_id TEXT,
        alert_type TEXT,
        severity TEXT,
        risk_score INTEGER,
        confidence_score INTEGER,
        description TEXT,
        status TEXT,
        created_at TEXT,
        observation_count INTEGER,
        FOREIGN KEY(threat_id) REFERENCES threats(threat_id)
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (
        note_id INTEGER PRIMARY KEY AUTOINCREMENT,
        threat_id TEXT,
        note TEXT,
        created_at TEXT,
        FOREIGN KEY(threat_id) REFERENCES threats(threat_id)
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS quiz_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        overall_score INTEGER,
        category_scores TEXT,
        created_at TEXT
    )""")
    
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

if __name__ == "__main__":
    init_db()
