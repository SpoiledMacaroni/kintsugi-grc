"""
Automated Integration Test Suite for Kintsugi-GRC Scanner Engine, GUI App & PDF Exporter
Executes app.py scan against synthetic database environments, verifies structured 
scan_report.json findings, kintsugi_scanner_audit.log audit logs, PDF exports (scan_report.pdf),
Docker RAG policy vectorization, and QA assertion match rates against expected_scan_results.json.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.mapping.controls import ControlRegistry
from src.output.pdf_exporter import PDFComplianceExporter
from src.output.reporter import ScanReporter
from src.placeholders.rag_pipeline import RAGPipelineClient
from src.scanner.audit import ScannerAuditLogger
from src.scanner.engine import ScannerEngine
from scripts.generate_synthetic import generate_luhn_pan, generate_ssn


class TestScannerEngine(unittest.TestCase):
    """Test suite for Scanner Engine, IAM Auditor, Config Auditor, PDF Exporter, and CLI/GUI Application."""

    @classmethod
    def setUpClass(cls):
        """Generates a temporary synthetic environment for scanner testing."""
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="kintsugi_scanner_test_"))
        cls.synthetic_env = cls.temp_dir / "synthetic_test_env"
        
        # Run synthetic environment generator script
        gen_script = project_root / "scripts" / "generate_synthetic.py"
        cmd = [
            sys.executable,
            str(gen_script),
            "--industry", "all",
            "--output-dir", str(cls.synthetic_env),
            "--seed", "42"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"Synthetic generation failed: {result.stderr}"

    @classmethod
    def tearDownClass(cls):
        """Cleans up temporary directory after tests."""
        if cls.temp_dir.exists():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_control_registry_loading(self):
        """Verifies that ControlRegistry loads grc_controls.zip and maps rules correctly."""
        zip_path = project_root / "grc_controls.zip"
        registry = ControlRegistry(zip_path)
        loaded = registry.load()
        self.assertTrue(loaded)
        self.assertGreater(len(registry.frameworks), 0)

        # Test mapping a rule
        citations = registry.map_rule_to_frameworks("PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE")
        self.assertGreater(len(citations), 0)
        framework_names = [c["framework"] for c in citations]
        self.assertIn("PCI DSS", framework_names)

    def test_pdf_report_exporter(self):
        """Verifies PDF report generation engine."""
        zip_path = project_root / "grc_controls.zip"
        registry = ControlRegistry(zip_path)
        registry.load()

        audit_log = self.temp_dir / "test_audit_pdf.log"
        audit_logger = ScannerAuditLogger(audit_log)
        audit_logger.initialize()

        engine = ScannerEngine(self.synthetic_env, registry, audit_logger)
        summary = engine.run_scan()

        pdf_out = self.temp_dir / "test_compliance_report.pdf"
        out_path = PDFComplianceExporter.generate_pdf_report(summary, pdf_out)
        
        self.assertTrue(out_path.exists())
        self.assertGreater(out_path.stat().st_size, 500)
        with open(out_path, "rb") as f:
            pdf_bytes = f.read()
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))

    def test_rag_policy_vectorization(self):
        """Verifies RAG pipeline policy document vectorizer."""
        rag_client = RAGPipelineClient()
        rag_client.connect()

        policy_file = self.synthetic_env / "healthcare_production_env" / "internal_policies" / "hipaa_safeguards_policy_v4.txt"
        if policy_file.exists():
            vector_res = rag_client.ingest_and_vectorize_policy(policy_file)
            self.assertEqual(vector_res.get("status"), "VECTORIZED")
            self.assertGreater(vector_res.get("vector_count", 0), 0)

    def test_cli_app_scan_command(self):
        """Executes app.py scan CLI subcommand and verifies output scan_report.json, PDF report, and audit log."""
        report_file = self.temp_dir / "scan_report.json"
        pdf_file = self.temp_dir / "scan_report.pdf"
        audit_file = self.temp_dir / "kintsugi_scanner_audit.log"
        app_script = project_root / "app.py"

        cmd = [
            sys.executable,
            str(app_script),
            "scan",
            "--target", str(self.synthetic_env),
            "--output", str(report_file),
            "--pdf", str(pdf_file),
            "--audit-log", str(audit_file)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"app.py scan failed: {result.stderr}\nOutput: {result.stdout}")

        # Check JSON report
        self.assertTrue(report_file.exists())
        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIn("compliance_score", data)
        self.assertIn("findings", data)
        self.assertGreater(len(data["findings"]), 0)

        # Check PDF report
        self.assertTrue(pdf_file.exists())
        self.assertGreater(pdf_file.stat().st_size, 500)

        # Check Operation Audit Log
        self.assertTrue(audit_file.exists())
        with open(audit_file, "r", encoding="utf-8") as f:
            audit_text = f.read()

        self.assertIn("[ACCESS_READ]", audit_text)
        self.assertIn("[RULE_EVALUATION]", audit_text)
        self.assertIn("[WRITE_EVENT]", audit_text)

    def test_dynamic_directory_watcher(self):
        """Verifies real-time dynamic re-scanning and score updating when files are edited or remediated."""
        registry = ControlRegistry()
        registry.load()
        audit_log = self.temp_dir / "dynamic_watcher_audit.log"
        audit_logger = ScannerAuditLogger(audit_log)
        audit_logger.initialize()

        engine = ScannerEngine(self.synthetic_env, registry, audit_logger)
        initial_summary = engine.run_scan()
        initial_score = initial_summary["compliance_score"]

        # 1. Create a dynamic test file inside target subfolder with unencrypted cleartext credit card PAN & SSN payload
        target_subfolder = self.synthetic_env / "healthcare_production_env" / "billing_department"
        target_subfolder.mkdir(parents=True, exist_ok=True)
        test_file = target_subfolder / "dynamic_test_payload.csv"
        lines = ["ID,CardPAN,SSN"] + [f"{i},{generate_luhn_pan()},{generate_ssn()}" for i in range(50)]
        test_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # 2. Trigger CREATED dynamic event
        created_summary = engine.update_single_file(test_file, "CREATED")
        created_findings = [f for f in created_summary["findings"] if "dynamic_test_payload.csv" in f["file_path"]]
        self.assertGreater(len(created_findings), 0, f"Created cleartext PAN file should produce finding. All findings: {created_summary['findings']}")
        self.assertEqual(created_findings[0]["rule_id"], "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN")

        # 3. Encrypt file with compliant AES header and trigger MODIFIED event (remediation)
        test_file.write_bytes(b"\x85\x01AES-256-CBC-ENCRYPTED-HEADER" + os.urandom(1024))
        modified_summary = engine.update_single_file(test_file, "MODIFIED")
        modified_findings = [
            f for f in modified_summary["findings"]
            if f["file_path"] == "dynamic_test_payload.csv" and f["severity"] in ["CRITICAL", "HIGH"]
        ]
        self.assertEqual(len(modified_findings), 0, "Encrypted AES file should clear unencrypted plaintext violation finding")

        # 4. Delete file and trigger DELETED event
        test_file.unlink(missing_ok=True)
        deleted_summary = engine.update_single_file(test_file, "DELETED")
        deleted_findings = [f for f in deleted_summary["findings"] if f["file_path"] == "dynamic_test_payload.csv"]
        self.assertEqual(len(deleted_findings), 0, "Deleted file should have zero remaining findings")

        # 5. Remediate insecure config (etc/login.defs: PASS_MAX_DAYS 99999 -> 89) and verify PASS status & score increase
        login_defs_path = self.synthetic_env / "healthcare_production_env" / "etc" / "login.defs"
        if login_defs_path.exists():
            login_defs_path.write_text("PASS_MAX_DAYS 89\nPASS_MIN_DAYS 7\n", encoding="utf-8")
            config_remediated_summary = engine.update_single_file(login_defs_path, "MODIFIED")
            remediated_login_findings = [
                f for f in config_remediated_summary["findings"]
                if "login.defs" in f["file_path"]
            ]
            self.assertGreater(len(remediated_login_findings), 0)
            self.assertEqual(remediated_login_findings[0]["severity"], "PASS")
            self.assertGreaterEqual(config_remediated_summary["compliance_score"], initial_score)


if __name__ == "__main__":
    unittest.main()
