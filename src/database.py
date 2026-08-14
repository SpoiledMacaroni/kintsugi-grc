import sqlite3
import os

DB_PATH = "imports/kintsugi.db"

def init_db(db_path=DB_PATH):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Compliance Rules Metadata (Replaces metadata.pkl)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS compliance_rules (
        id INTEGER PRIMARY KEY,
        clause_id TEXT UNIQUE NOT NULL,
        standard TEXT NOT NULL,
        section TEXT NOT NULL,
        context TEXT NOT NULL,
        remediation TEXT NOT NULL,
        chunk_type TEXT DEFAULT 'normative'
    )
    """)

    # Migration guard: add chunk_type to existing databases that predate this column
    existing_columns = {row[1] for row in cursor.execute("PRAGMA table_info(compliance_rules)")}
    if "chunk_type" not in existing_columns:
        cursor.execute("ALTER TABLE compliance_rules ADD COLUMN chunk_type TEXT DEFAULT 'normative'")
    
    # 2. Historical Scan Execution Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (
        scan_id TEXT PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        target_directory TEXT NOT NULL,
        files_scanned INTEGER DEFAULT 0,
        violations_found INTEGER DEFAULT 0,
        status TEXT NOT NULL
    )
    """)
    
    # 3. Discovered Vulnerabilities
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS violations (
        violation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        filepath TEXT NOT NULL,
        violation_code TEXT NOT NULL,
        entropy REAL,
        permissions TEXT,
        patterns_matched TEXT,
        FOREIGN KEY(scan_id) REFERENCES scan_history(scan_id)
    )
    """)
    
    # 4. Compiled Remediation Advisory Cards
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_cards (
        card_id INTEGER PRIMARY KEY AUTOINCREMENT,
        violation_id INTEGER NOT NULL,
        clause_id TEXT NOT NULL,
        standard TEXT NOT NULL,
        risk_statement TEXT NOT NULL,
        remediation_command TEXT NOT NULL,
        rationale TEXT NOT NULL,
        execution_mode TEXT NOT NULL,
        FOREIGN KEY(violation_id) REFERENCES violations(violation_id)
    )
    """)
    
    conn.commit()
    conn.close()
    print(f"Database initialized successfully at {db_path}")

if __name__ == "__main__":
    init_db()
