import os
import sys
import unittest
import sqlite3
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.ingester import RelationalPolicyIngester
from src.orchestrator import RelationalRAGOrchestrator
from src.logger import RelationalScanLogger
from src.database import DB_PATH

class TestKintsugiSQLiteIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n====== STARTING KINTSUGI SQLITE END-TO-END VERIFICATION ======")
        
        # Execute repository synthetic generator
        generator = "scripts/generate_synthetic.py"
        if os.path.exists(generator):
            subprocess.run([sys.executable, generator, "--industry", "healthcare", "--output-dir", "./test_env", "--seed", "42"], check=True)
            
        # Ingest and Seed FAISS + SQLite
        cls.ingester = RelationalPolicyIngester()
        cls.ingester.build_index(db_path=DB_PATH)
        
        cls.orchestrator = RelationalRAGOrchestrator(db_path=DB_PATH)
        cls.logger = RelationalScanLogger(db_path=DB_PATH)

    def test_end_to_end_sqlite_pipeline(self):
        # 1. Simulate scanned file finding
        vulnerability_payload = {
            "filepath": "simulated_data/medical_records.csv",
            "violation_code": "ERR-OCTAL-WORLD-WRITABLE",
            "permissions": "0o777"
        }
        
        # 2. Compile Card via RAG
        card = self.orchestrator.generate_advisory(
            vulnerability_payload['violation_code'],
            vulnerability_payload
        )
        self.assertEqual(card['execution_mode'], "DETERMINISTIC_SINGLE_MODEL_RAG")
        
        # 3. Log Scan Results to Database
        vulnerability_payload['remediation_card'] = card
        scan_id = self.logger.log_scan_results("simulated_data", 1, [vulnerability_payload])
        
        # 4. Query Database and Assert Core Schema Records Exist
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT target_directory, violations_found FROM scan_history WHERE scan_id = ?", (scan_id,))
        scan_rec = cursor.fetchone()
        self.assertEqual(scan_rec[0], "simulated_data")
        self.assertEqual(scan_rec[1], 1)
        
        cursor.execute("SELECT filepath, violation_code FROM violations WHERE scan_id = ?", (scan_id,))
        violation_rec = cursor.fetchone()
        self.assertEqual(violation_rec[0], "simulated_data/medical_records.csv")
        self.assertEqual(violation_rec[1], "ERR-OCTAL-WORLD-WRITABLE")
        
        conn.close()
        print("\nSUCCESS: End-to-end SQLite integration verified. All rows mapped.")

if __name__ == "__main__":
    unittest.main()
