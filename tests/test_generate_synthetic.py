"""
tests/test_generate_synthetic.py

Automated integration test suite for scripts/generate_synthetic.py.
Verifies synthetic environment creation, file health, magic headers,
local key manifest storage, Luhn-10 PAN validity, Active Directory exports,
and defensive execution scoping boundaries.
"""

import json
import os
import sys
import unittest
import zipfile

from pathlib import Path
from tempfile import TemporaryDirectory

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.generate_synthetic import (
    generate_luhn_pan,
    validate_path_in_scope,
    main as generate_main
)

def is_valid_luhn(card_number: str) -> bool:
    """Helper validator for Luhn-10 checksum."""
    digits = [int(c) for c in card_number if c.isdigit()]
    total = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            d = digit * 2
            if d > 9:
                d -= 9
            total += d
        else:
            total += digit
    return total % 10 == 0

class TestSyntheticGenerator(unittest.TestCase):

    def test_generate_luhn_pan_checksum(self):
        """Verify generated PANs pass Luhn-10 checksum algorithm."""
        for prefix in ["4", "51", "37"]:
            for _ in range(50):
                pan = generate_luhn_pan(prefix=prefix, length=16)
                self.assertEqual(len(pan), 16)
                self.assertTrue(pan.startswith(prefix))
                self.assertTrue(is_valid_luhn(pan), f"Generated PAN failed Luhn-10: {pan}")

    def test_scoping_security_boundary(self):
        """Verify path validation raises RuntimeError when targeting outside root boundary."""
        with TemporaryDirectory() as tmp_dir:
            root_dir = Path(tmp_dir) / "safe_root"
            root_dir.mkdir()

            inside_path = root_dir / "subdir" / "file.txt"
            validate_path_in_scope(inside_path, root_dir)  # Should pass without error

            outside_path = Path(tmp_dir) / "outside.txt"
            with self.assertRaises(RuntimeError) as ctx:
                validate_path_in_scope(outside_path, root_dir)
            self.assertIn("SECURITY VIOLATION", str(ctx.exception))

    def test_synthetic_generation_healthcare(self):
        """Verify healthcare environment generation, file creation, and permissions."""
        with TemporaryDirectory() as tmp_dir:
            test_dir = Path(tmp_dir) / "test_hc"
            test_dir.mkdir()

            orig_argv = sys.argv
            sys.argv = ["generate_synthetic.py", "--industry", "healthcare", "--output-dir", str(test_dir), "--seed", "42"]
            try:
                generate_main()
            finally:
                sys.argv = orig_argv

            env_root = test_dir / "healthcare_production_env"
            self.assertTrue(env_root.exists())

            # Check key manifest
            manifest_path = test_dir / ".keys" / "manifest.json"
            self.assertTrue(manifest_path.exists())
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            self.assertGreater(manifest_data["total_keys"], 0)
            self.assertGreater(len(manifest_data["keys"]), 0)

            # Check Category A GPG file magic header
            gpg_file = env_root / "patient_records" / "ehr_db_master.gpg"
            self.assertTrue(gpg_file.exists())
            with open(gpg_file, "rb") as f:
                header = f.read(2)
            self.assertEqual(header, b"\x85\x01")

            # Check Category C ASCII Armored block
            asc_file = env_root / "patient_records" / "patient_consent_forms.asc"
            self.assertTrue(asc_file.exists())
            with open(asc_file, "r", encoding="utf-8") as f:
                asc_content = f.read()
            self.assertIn("-----BEGIN KINTSUGI SECURE BLOCK-----", asc_content)
            self.assertIn("-----END KINTSUGI SECURE BLOCK-----", asc_content)

            # Check Active Directory exports
            ad_csv = env_root / "etc" / "ad" / "ad_users_export.csv"
            ad_json = env_root / "etc" / "ad" / "ad_sid_uid_map.json"
            self.assertTrue(ad_csv.exists())
            self.assertTrue(ad_json.exists())
            with open(ad_json, "r", encoding="utf-8") as f:
                ad_map = json.load(f)
            self.assertIn("identity_mappings", ad_map)
            self.assertIn("S-1-5-21-3623811015-3361044348-30300820-1001", ad_map["identity_mappings"])

            # Check expected scan findings JSON & Audit Log
            exp_json_path = test_dir / "expected_scan_results.json"
            audit_log_path = test_dir / "synthetic_generation_audit.log"
            self.assertTrue(exp_json_path.exists())
            self.assertTrue(audit_log_path.exists())
            with open(exp_json_path, "r", encoding="utf-8") as f:
                exp_data = json.load(f)
            self.assertGreater(exp_data["total_expected_findings"], 0)
            self.assertGreater(len(exp_data["expected_findings"]), 0)
            with open(audit_log_path, "r", encoding="utf-8") as f:
                audit_content = f.read()
            self.assertIn("Constructing Healthcare Environment", audit_content)

            # Check mock system TLS policy files
            openssl_cnf = env_root / "etc" / "ssl" / "openssl.cnf"
            crypto_state = env_root / "etc" / "crypto-policies" / "state" / "current"
            nginx_ssl = env_root / "etc" / "nginx" / "conf.d" / "ssl_policy.conf"
            schannel_reg = env_root / "etc" / "registry" / "hklm_schannel_export.reg"
            self.assertTrue(openssl_cnf.exists())
            self.assertTrue(crypto_state.exists())
            self.assertTrue(nginx_ssl.exists())
            self.assertTrue(schannel_reg.exists())
            with open(openssl_cnf, "r", encoding="utf-8") as f:
                self.assertIn("MinProtocol = TLSv1.0", f.read())

    def test_synthetic_generation_all_industries(self):
        """Verify all 4 industry production environments generate cleanly."""
        with TemporaryDirectory() as tmp_dir:
            test_dir = Path(tmp_dir) / "test_all"
            test_dir.mkdir()

            orig_argv = sys.argv
            sys.argv = ["generate_synthetic.py", "--industry", "all", "--output-dir", str(test_dir), "--seed", "123"]
            try:
                generate_main()
            finally:
                sys.argv = orig_argv

            expected_envs = [
                "healthcare_production_env",
                "merchant_production_env",
                "finance_production_env",
                "banking_production_env"
            ]
            for env in expected_envs:
                self.assertTrue((test_dir / env).exists(), f"Missing environment: {env}")

            # Verify Zip Bomb safety case in finance
            zip_bomb = test_dir / "finance_production_env" / "system_backups" / "decompression_safety_check.zip"
            self.assertTrue(zip_bomb.exists())
            with zipfile.ZipFile(zip_bomb, "r") as zf:
                namelist = zf.namelist()
                self.assertIn("null_stream_10mb.raw", namelist)
                info = zf.getinfo("null_stream_10mb.raw")
                self.assertEqual(info.file_size, 10 * 1024 * 1024)  # 10MB uncompressed

if __name__ == "__main__":
    unittest.main()
