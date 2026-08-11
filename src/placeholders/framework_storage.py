"""
Kintsugi-GRC Framework Data Storage & Reference Client (Tenzin's Component Integration)
Provides database persistence for compliance frameworks, control mappings, 
historical audit logs, and discovered violations in imports/kintsugi.db.
"""

import json
import logging
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from src.database import DB_PATH, init_db

logger = logging.getLogger("kintsugi_framework_storage")

class FrameworkStorageClient:
    """Persistent database client interfacing with imports/kintsugi.db."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        init_db(self.db_path)
        self.ready = True

    def get_framework_references(self, framework_id: str) -> Dict[str, Any]:
        """Returns control references for a requested GRC framework from SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM compliance_rules WHERE standard LIKE ?", (f"%{framework_id}%",))
            count = cursor.fetchone()[0]
            conn.close()
            return {
                "framework_id": framework_id,
                "status": "LOADED_SQLITE",
                "rules_indexed": count,
                "db_path": self.db_path
            }
        except Exception as e:
            logger.error(f"Failed to fetch framework references: {e}")
            return {"framework_id": framework_id, "status": "ERROR", "message": str(e)}

    def save_scan_history(self, scan_summary: Dict[str, Any]) -> bool:
        """Persists scan execution log, discovered violations, and remediation cards into SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            scan_id = str(uuid.uuid4())
            target_dir = scan_summary.get("target_directory", "N/A")
            total_files = scan_summary.get("total_files_scanned", 0)
            total_findings = scan_summary.get("total_findings", 0)

            # 1. Insert into scan_history
            cursor.execute("""
                INSERT INTO scan_history (scan_id, target_directory, files_scanned, violations_found, status)
                VALUES (?, ?, ?, ?, ?)
            """, (scan_id, target_dir, total_files, total_findings, "COMPLETED"))

            # 2. Insert violations and remediation cards
            for finding in scan_summary.get("findings", []):
                rel_path = finding.get("file_path", "N/A")
                rule_id = finding.get("rule_id", "GENERAL_VIOLATION")
                details = finding.get("details", {})
                entropy = details.get("entropy", details.get("body_entropy", 0.0))
                mode = details.get("mode", "N/A")
                patterns = json.dumps(details)

                cursor.execute("""
                    INSERT INTO violations (scan_id, filepath, violation_code, entropy, permissions, patterns_matched)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, rel_path, rule_id, entropy, str(mode), patterns))

                violation_id = cursor.lastrowid
                advisory = finding.get("rag_advisory", {})
                if advisory and violation_id:
                    cursor.execute("""
                        INSERT INTO remediation_cards (violation_id, clause_id, standard, risk_statement, remediation_command, rationale, execution_mode)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        violation_id,
                        advisory.get("clause_id", "N/A"),
                        advisory.get("standard", "N/A"),
                        advisory.get("risk_statement", "N/A"),
                        advisory.get("remediation_command", "N/A"),
                        advisory.get("rationale", "N/A"),
                        advisory.get("execution_mode", "DETERMINISTIC_SINGLE_MODEL_RAG")
                    ))

            conn.commit()
            conn.close()
            logger.info(f"Persisted scan history ({total_findings} findings) under Scan ID '{scan_id}' in '{self.db_path}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to save scan history to SQLite database: {e}")
            return False
