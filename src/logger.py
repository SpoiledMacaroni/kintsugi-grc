import sqlite3
import uuid
from src.database import DB_PATH

class RelationalScanLogger:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def log_scan_results(self, target_directory, file_count, findings):
        scan_id = str(uuid.uuid4())
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. Log Scan History Session
        cursor.execute("""
            INSERT INTO scan_history (scan_id, target_directory, files_scanned, violations_found, status)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, target_directory, file_count, len(findings), "COMPLETED"))
        
        # 2. Log Individual Violations & Cards
        for f in findings:
            cursor.execute("""
                INSERT INTO violations (scan_id, filepath, violation_code, entropy, permissions, patterns_matched)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, f['filepath'], f['violation_code'], f.get('entropy'), f.get('permissions'), str(f.get('patterns_matched')) if f.get('patterns_matched') else None))
            
            violation_id = cursor.lastrowid
            card = f['remediation_card']
            
            cursor.execute("""
                INSERT INTO remediation_cards (violation_id, clause_id, standard, risk_statement, remediation_command, rationale, execution_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (violation_id, card['clause_id'], card['standard'], card['risk_statement'], card['remediation_command'], card['rationale'], card['execution_mode']))
            
        conn.commit()
        conn.close()
        print(f"Logged compliance scanning metrics under Scan ID: {scan_id}")
        return scan_id
