#!/usr/bin/env python3
"""
scripts/generate_synthetic.py

Production-Grade Synthetic Production Environment Generator for Kintsugi-GRC.
Maps system-level metadata to HIPAA Technical Safeguards (§164.312), HITRUST CSF e1,
and PCI-DSS v4.0.1.

Generates realistic, nested filesystem host environments for target industries:
- Healthcare (healthcare_production_env/)
- Merchant (merchant_production_env/)
- Finance (finance_production_env/)
- Banking (banking_production_env/)

Implements true cryptographic operations, compression anomalies, statistical edge cases,
Active Directory identity exports (SID/UUID/UID/GID), and compliance violations.

Usage:
    python3 scripts/generate_synthetic.py --industry healthcare --output-dir ./test_env --seed 42 --verbose
"""

import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import random
import secrets
import shutil
import sys
import uuid
import zlib
import subprocess
from pathlib import Path
import zipfile

try:
    try:
        from src.dep_check import ensure_dependencies
        ensure_dependencies(["cryptography"])
    except ImportError:
        pass
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
except ModuleNotFoundError:
    print("[Kintsugi-GRC] Missing required dependency 'cryptography'. Automatically installing via pip...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography>=42.0.0"])
    import site
    import importlib
    user_site = site.getusersitepackages()
    if user_site and user_site not in sys.path and os.path.exists(user_site):
        sys.path.insert(0, user_site)
    importlib.invalidate_caches()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend

# -----------------------------------------------------------------------------
# LOGGING SETUP
# -----------------------------------------------------------------------------
logger = logging.getLogger("kintsugi_synthetic")

def setup_logging(output_base: Path = None, verbose: bool = False) -> None:
    for h in logger.handlers:
        h.close()
    logger.handlers.clear()
    
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    stream_handler.setFormatter(stream_formatter)
    logger.addHandler(stream_handler)

    if output_base:
        audit_file = output_base / "synthetic_generation_audit.log"
        validate_path_in_scope(audit_file, output_base)
        file_handler = logging.FileHandler(audit_file, mode="w", encoding="utf-8")
        file_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [AUDIT_LOG] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

# -----------------------------------------------------------------------------
# DEFENSIVE SCOPING & CROSS-PLATFORM PERMISSION UTILITIES
# -----------------------------------------------------------------------------
def safe_chmod(file_path: Path, mode: int) -> None:
    """Cross-platform helper to set file permissions safely."""
    try:
        if os.name == 'posix':
            os.chmod(file_path, mode)
        else:
            os.chmod(file_path, mode)
    except Exception as e:
        logger.warning(f"Could not set permission {oct(mode)} on {file_path}: {e}")

def validate_path_in_scope(target_path: Path, root_boundary: Path) -> None:
    """Enforces strict execution scoping. Prevents writing outside target root."""
    resolved_target = target_path.resolve()
    resolved_root = root_boundary.resolve()
    if not (resolved_target == resolved_root or resolved_root in resolved_target.parents):
        raise RuntimeError(
            f"SECURITY VIOLATION: Refusing to write outside root boundary! "
            f"Target: {resolved_target}, Root: {resolved_root}"
        )

# -----------------------------------------------------------------------------
# CRYPTOGRAPHIC & IDENTIFIER GENERATORS
# -----------------------------------------------------------------------------
GPG_MAGIC_HEADER = b"\x85\x01"  # GPG-style packet header

def derive_key(password: str) -> bytes:
    """Derives a 256-bit AES key using SHA-256 hashing."""
    return hashlib.sha256(password.encode("utf-8")).digest()

def encrypt_aes_256_cbc(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-256-CBC with PKCS7 padding.
    Returns (iv, ciphertext_with_magic_header).
    """
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    payload = GPG_MAGIC_HEADER + iv + ciphertext
    return iv, payload

def encrypt_aes_256_ecb(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-ECB with PKCS7 padding.
    Simulates insecure block pattern leaks.
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def generate_luhn_pan(prefix: str = "4", length: int = 16) -> str:
    """Generates a mathematically valid Primary Account Number (PAN) passing Luhn-10."""
    digits = [int(x) for x in prefix] + [random.randint(0, 9) for _ in range(length - 1 - len(prefix))]
    
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:  # Odd position from right in 1-based indexing (doubled)
            d = digit * 2
            if d > 9:
                d -= 9
            total += d
        else:
            total += digit
            
    check_digit = (10 - (total % 10)) % 10
    digits.append(check_digit)
    return "".join(map(str, digits))

def generate_ssn() -> str:
    """Generates realistic Social Security Number formatted as XXX-XX-XXXX."""
    area = random.randint(100, 899)
    group = random.randint(10, 99)
    serial = random.randint(1000, 9999)
    return f"{area:03d}-{group:02d}-{serial:04d}"

def generate_mock_ssh_keypair() -> tuple[str, str]:
    """Generates a mock SSH RSA key pair for testing transmission protection assets."""
    priv_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + base64.b64encode(secrets.token_bytes(256)).decode("utf-8")
        + "\n-----END RSA PRIVATE KEY-----\n"
    )
    pub_key = f"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ{secrets.token_hex(32)} root@kintsugi-host"
    return priv_key, pub_key

# -----------------------------------------------------------------------------
# KEY MANAGEMENT & MANIFEST SYSTEM
# -----------------------------------------------------------------------------
class KeyManager:
    """Manages local encryption keys, IVs, passwords, and SSH keys in .keys/manifest.json."""
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.keys_dir = root_dir / ".keys"
        self.manifest_path = self.keys_dir / "manifest.json"
        self.backup_path = self.keys_dir / "master_keys.bak"
        self.readme_path = self.keys_dir / "KEYS_README.md"
        self.entries = []

    def initialize(self):
        validate_path_in_scope(self.keys_dir, self.root_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        safe_chmod(self.keys_dir, 0o700)

    def record_key(self, relative_path: str, algorithm: str, key_hex: str, password: str = "", iv_hex: str = "", extra: dict = None):
        entry = {
            "file_path": Path(relative_path).as_posix(),
            "algorithm": algorithm,
            "key_hex": key_hex,
            "key_sha256": hashlib.sha256(bytes.fromhex(key_hex)).hexdigest() if key_hex != "N/A" else "N/A",
            "password": password,
            "iv_hex": iv_hex,
            "created_at": "2026-08-10T15:00:00Z"
        }
        if extra:
            entry.update(extra)
        self.entries.append(entry)

    def save(self):
        validate_path_in_scope(self.manifest_path, self.root_dir)
        content = {
            "system": "Kintsugi-GRC Synthetic Key Manifest",
            "security_warning": "DO NOT UPLOAD TO GITHUB. Local testing keys only.",
            "total_keys": len(self.entries),
            "keys": self.entries
        }
        json_bytes = json.dumps(content, indent=2).encode("utf-8")
        
        with open(self.manifest_path, "wb") as f:
            f.write(json_bytes)
        safe_chmod(self.manifest_path, 0o600)

        with open(self.backup_path, "wb") as f:
            f.write(json_bytes)
        safe_chmod(self.backup_path, 0o600)

        readme = (
            "# Kintsugi-GRC Synthetic Environment Key Manifest\n\n"
            "This folder contains local encryption keys, initialization vectors (IVs), "
            "derivation passwords, and mock SSH keypairs for testing decryption engines.\n\n"
            "## Safety & Security\n"
            "- Key files in `.keys/` are excluded by `.gitignore`.\n"
            "- Keys are saved in `manifest.json` and backed up in `master_keys.bak`.\n"
            "- Use `manifest.json` to verify decryption pipeline outputs.\n"
        )
        with open(self.readme_path, "w", encoding="utf-8") as f:
            f.write(readme)
        safe_chmod(self.readme_path, 0o644)
        logger.info(f"Recorded {len(self.entries)} encryption keys in {self.manifest_path.as_posix()}")

class ExpectedResultsRecorder:
    """Manages expected scan findings in expected_scan_results.json for QA scanner assertion matching."""
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.output_json = root_dir / "expected_scan_results.json"
        self.output_bak = root_dir / ".keys" / "expected_scan_results.bak"
        self.findings = []

    def record_finding(self, relative_path: str, expected_classification: str, category: str, compliance_status: str, rule_ids: list, severity: str = "INFO", details: dict = None):
        entry = {
            "file_path": Path(relative_path).as_posix(),
            "expected_classification": expected_classification,
            "category": category,
            "compliance_status": compliance_status,
            "severity": severity,
            "rule_ids": rule_ids
        }
        if details:
            entry.update(details)
        self.findings.append(entry)

    def save(self):
        validate_path_in_scope(self.output_json, self.root_dir)
        content = {
            "system": "Kintsugi-GRC Expected Synthetic Scan Findings",
            "security_warning": "DO NOT UPLOAD TO GITHUB. Local QA test assertion target.",
            "total_expected_findings": len(self.findings),
            "expected_findings": self.findings
        }
        json_bytes = json.dumps(content, indent=2).encode("utf-8")
        with open(self.output_json, "wb") as f:
            f.write(json_bytes)
        safe_chmod(self.output_json, 0o644)

        self.output_bak.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_bak, "wb") as f:
            f.write(json_bytes)
        safe_chmod(self.output_bak, 0o600)
        logger.info(f"Recorded {len(self.findings)} expected scan findings in {self.output_json.relative_to(self.root_dir).as_posix()}")

# -----------------------------------------------------------------------------
# ACTIVE DIRECTORY & POSIX IDENTITY EXPORT BUILDER
# -----------------------------------------------------------------------------
def generate_active_directory_exports(etc_dir: Path, key_mgr: KeyManager, root_dir: Path):
    """Generates synthetic Active Directory user/group exports for UID/GID/SID access checking."""
    ad_dir = etc_dir / "ad"
    validate_path_in_scope(ad_dir, root_dir)
    ad_dir.mkdir(parents=True, exist_ok=True)

    users = [
        {"username": "jsmith", "role": "Doctor", "uid": 1001, "gid": 1001, "sid": "S-1-5-21-3623811015-3361044348-30300820-1001"},
        {"username": "mchen", "role": "BillingClerk", "uid": 1002, "gid": 1002, "sid": "S-1-5-21-3623811015-3361044348-30300820-1002"},
        {"username": "compliance_auditor", "role": "Auditor", "uid": 1003, "gid": 1000, "sid": "S-1-5-21-3623811015-3361044348-30300820-1003"},
        {"username": "svc_pos_terminal", "role": "POS_Service", "uid": 1004, "gid": 1002, "sid": "S-1-5-21-3623811015-3361044348-30300820-1004"},
        {"username": "bank_trader_01", "role": "Trader", "uid": 1005, "gid": 1003, "sid": "S-1-5-21-3623811015-3361044348-30300820-1005"},
        {"username": "root_admin", "role": "DomainAdmin", "uid": 0, "gid": 0, "sid": "S-1-5-21-3623811015-3361044348-30300820-500"},
        {"username": "daemon", "role": "SystemDaemon", "uid": 1, "gid": 1, "sid": "S-1-5-18"},
        {"username": "bin", "role": "SystemBin", "uid": 2, "gid": 2, "sid": "S-1-5-19"},
    ]

    csv_path = ad_dir / "ad_users_export.csv"
    json_path = ad_dir / "ad_sid_uid_map.json"

    validate_path_in_scope(csv_path, root_dir)
    validate_path_in_scope(json_path, root_dir)

    sid_map = {}
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "sAMAccountName", "userPrincipalName", "objectSid", "objectGUID",
            "uidNumber", "gidNumber", "primaryGroupID", "memberOf", "userAccountControl"
        ])
        for u in users:
            guid = str(uuid.uuid5(uuid.NAMESPACE_DNS, u["username"]))
            upn = f"{u['username']}@corp.kintsugi.internal"
            member_of = f"CN={u['role']}s,OU=Groups,DC=kintsugi,DC=internal;CN=Domain Users,OU=Groups,DC=kintsugi,DC=internal"
            uac = "512"  # Normal Account
            writer.writerow([
                u["username"], upn, u["sid"], guid,
                u["uid"], u["gid"], "513", member_of, uac
            ])
            sid_map[u["sid"]] = {
                "sAMAccountName": u["username"],
                "uidNumber": u["uid"],
                "gidNumber": u["gid"],
                "objectGUID": guid
            }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"ad_domain": "kintsugi.internal", "identity_mappings": sid_map}, f, indent=2)

    logger.info(f"Generated Active Directory exports at {csv_path.relative_to(root_dir).as_posix()}")

# -----------------------------------------------------------------------------
# PAYLOAD GENERATOR HELPERS (CATEGORIES A, B, C, D)
# -----------------------------------------------------------------------------

def generate_category_a_compliant_encrypted(file_path: Path, password: str, record_count: int, key_mgr: KeyManager, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """
    Category A: Baseline Compliant File (True AES-256-CBC Encryption).
    Prepend magic bytes \x85\x01. Produces H >= 7.92, 125 <= M <= 130, x^2 < 300.
    """
    validate_path_in_scope(file_path, root_dir)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Build realistic enterprise tabular payload (64KB - 256KB)
    lines = ["id,patient_name,ssn,diagnosis_icd10,credit_card,billing_amount,notes\n"]
    for i in range(record_count):
        lines.append(
            f"{i+1000},Patient_{i:04d},{generate_ssn()},E11.9,{generate_luhn_pan()},"
            f"{random.uniform(50.0, 4500.0):.2f},Confidential clinical encounter ledger entry for HIPAA audit.\n"
        )
    plaintext = "".join(lines).encode("utf-8")

    key = derive_key(password)
    iv, payload = encrypt_aes_256_cbc(plaintext, key)

    with open(file_path, "wb") as f:
        f.write(payload)
    safe_chmod(file_path, 0o600)  # Restricted database payload - Owner R/W

    key_mgr.record_key(
        file_path.relative_to(root_dir).as_posix(),
        "AES-256-CBC",
        key.hex(),
        password=password,
        iv_hex=iv.hex(),
        extra={"magic_bytes": "8501", "record_count": record_count, "payload_bytes": len(payload)}
    )
    if results_rec:
        results_rec.record_finding(
            file_path.relative_to(root_dir).as_posix(),
            "ENCRYPTED_COMPLIANT_AES_256_CBC",
            "Category_A",
            "PASS",
            ["HIPAA_164_312_a_2_iv", "HITRUST_09_v", "PCI_DSS_v4_3_5"],
            severity="PASS",
            details={"magic_header": "8501", "min_entropy": 7.92}
        )
    logger.info(f"[Category A] Created AES-256-CBC compliant file ({len(payload)} bytes): {file_path.relative_to(root_dir).as_posix()}")

def generate_category_b_false_positives(target_dir: Path, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """
    Category B: False Positive Fakes (High-Entropy Non-Encrypted Streams).
    - Raw zlib compressed streams
    - Unencrypted ZIP archives containing cleartext sensitive CSVs (Entropy ZIP Paradox)
    """
    validate_path_in_scope(target_dir, root_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_chmod(target_dir, 0o755)

    # 1. Raw zlib compressed file
    zlib_file = target_dir / "audit_log_archive.csv.zlib"
    validate_path_in_scope(zlib_file, root_dir)
    repetitive_text = ("COMPLIANCE_AUDIT_LOG_ENTRY_HIPAA_PCI_HITRUST_RULE_VERIFICATION_PASS\n" * 2000).encode("utf-8")
    compressed = zlib.compress(repetitive_text, level=9)
    with open(zlib_file, "wb") as f:
        f.write(compressed)
    safe_chmod(zlib_file, 0o640)  # Owner R/W, Group R
    if results_rec:
        results_rec.record_finding(
            zlib_file.relative_to(root_dir).as_posix(),
            "UNENCRYPTED_RAW_ZLIB_STREAM",
            "Category_B",
            "FAIL",
            ["KINTSUGI_ZIP_PARADOX_01"],
            severity="HIGH",
            details={"entropy_high": True, "chi_square_fail": True}
        )
    logger.info(f"[Category B] Created raw zlib compressed file ({len(compressed)} bytes): {zlib_file.relative_to(root_dir).as_posix()}")

    # 2. ZIP Archive with cleartext CSV containing SSNs and PANs
    zip_file = target_dir / "unencrypted_patient_export.zip"
    validate_path_in_scope(zip_file, root_dir)
    
    lines = ["patient_id,full_name,ssn,pan_card,dob\n"]
    for i in range(150):
        lines.append(f"{i+1},Unencrypted_User_{i},{generate_ssn()},{generate_luhn_pan()},1985-04-12\n")
    csv_bytes = "".join(lines).encode("utf-8")

    with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cleartext_patient_records.csv", csv_bytes)
    safe_chmod(zip_file, 0o644)  # Owner R/W, Group/Other R
    if results_rec:
        results_rec.record_finding(
            zip_file.relative_to(root_dir).as_posix(),
            "UNENCRYPTED_ZIP_ARCHIVE_WITH_PHI",
            "Category_B",
            "FAIL",
            ["HIPAA_164_312_e_1", "PCI_DSS_v4_4_2_1"],
            severity="CRITICAL",
            details={"contained_files": ["cleartext_patient_records.csv"]}
        )
    logger.info(f"[Category B] Created unencrypted ZIP archive ({zip_file.stat().st_size} bytes): {zip_file.relative_to(root_dir).as_posix()}")

def generate_category_c_false_negatives(target_dir: Path, password: str, key_mgr: KeyManager, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """
    Category C: False Negative Fakes (Low Raw Entropy, Hybrid, & Micro Payloads).
    - Heuristic 1: ASCII Armored Block (Base64 wrapper over ciphertext)
    - Heuristic 2: Hybrid File (512-byte cleartext ASCII header + true AES ciphertext)
    - Heuristic 3: Micro Payload (32-byte encrypted token)
    """
    validate_path_in_scope(target_dir, root_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_chmod(target_dir, 0o700)  # Restricted sensitive payload directory

    key = derive_key(password)

    # Heuristic 1: ASCII Armored Payload
    asc_file = target_dir / "patient_consent_forms.asc"
    validate_path_in_scope(asc_file, root_dir)
    raw_plaintext = ("HIPAA Consent Form Records; Patient Consent Signed ID=" + secrets.token_hex(16) + "\n") * 500
    iv, payload = encrypt_aes_256_cbc(raw_plaintext.encode("utf-8"), key)
    b64_payload = base64.b64encode(payload).decode("utf-8")
    formatted_b64 = "\n".join(b64_payload[i:i+64] for i in range(0, len(b64_payload), 64))
    armored = (
        "-----BEGIN KINTSUGI SECURE BLOCK-----\n"
        "Version: Kintsugi-v1.0\n"
        "Comment: Cryptographic ASCII Armored Payload\n\n"
        + formatted_b64 +
        "\n-----END KINTSUGI SECURE BLOCK-----\n"
    )
    with open(asc_file, "w", encoding="utf-8") as f:
        f.write(armored)
    safe_chmod(asc_file, 0o600)  # Owner R/W
    key_mgr.record_key(asc_file.relative_to(root_dir).as_posix(), "AES-256-CBC-ASCII-ARMOR", key.hex(), password=password, iv_hex=iv.hex())
    if results_rec:
        results_rec.record_finding(
            asc_file.relative_to(root_dir).as_posix(),
            "ASCII_ARMORED_ENCRYPTED_BLOCK",
            "Category_C",
            "PASS",
            ["KINTSUGI_ASCII_DECODER_01"],
            severity="PASS"
        )
    logger.info(f"[Category C - Heuristic 1] Created ASCII Armored block: {asc_file.relative_to(root_dir).as_posix()}")

    # Heuristic 2: Hybrid Plaintext Header + AES Ciphertext Payload
    hybrid_file = target_dir / "patient_encounters_2026.csv"
    validate_path_in_scope(hybrid_file, root_dir)
    header_str = (
        "FileType=PatientRecord; Owner=uid_1001; CARD_CLEAR=4111111111111111; "
        "Description=Confidential patient chart audit log for HIPAA §164.312 verification; "
        "Classification=CONFIDENTIAL; Status=PENDING_ENCRYPTION_REVIEW; "
    )
    # Pad header to exactly 512 bytes with spaces
    header_bytes = header_str.encode("utf-8")
    if len(header_bytes) < 512:
        header_bytes += b" " * (512 - len(header_bytes))
    else:
        header_bytes = header_bytes[:512]

    # Encrypted body (64KB)
    body_lines = ["encounter_id,patient_id,notes\n"] + [f"{i},P_{i:04d},Clinical chart notes detail...\n" for i in range(1200)]
    iv_hy, body_cipher = encrypt_aes_256_cbc("".join(body_lines).encode("utf-8"), key)

    hybrid_bytes = header_bytes + body_cipher
    with open(hybrid_file, "wb") as f:
        f.write(hybrid_bytes)
    safe_chmod(hybrid_file, 0o640)  # Owner R/W, Group R
    key_mgr.record_key(hybrid_file.relative_to(root_dir).as_posix(), "AES-256-CBC-HYBRID", key.hex(), password=password, iv_hex=iv_hy.hex())
    if results_rec:
        results_rec.record_finding(
            hybrid_file.relative_to(root_dir).as_posix(),
            "HYBRID_HEADER_ENCRYPTED_PAYLOAD",
            "Category_C",
            "PASS",
            ["KINTSUGI_SLIDING_WINDOW_256B"],
            severity="PASS",
            details={"cleartext_header_bytes": 512}
        )
    logger.info(f"[Category C - Heuristic 2] Created Hybrid file (512B header + {len(body_cipher)}B AES): {hybrid_file.relative_to(root_dir).as_posix()}")

    # Heuristic 3: Micro Payload (32 bytes)
    micro_file = target_dir / "patient_access_token.bin"
    validate_path_in_scope(micro_file, root_dir)
    iv_m, micro_payload = encrypt_aes_256_cbc(b"SECRET_32B_TOKEN", key)
    # Truncate/slice payload to 32 bytes exact
    micro_32b = micro_payload[:32]
    with open(micro_file, "wb") as f:
        f.write(micro_32b)
    safe_chmod(micro_file, 0o600)  # Owner R/W
    key_mgr.record_key(micro_file.relative_to(root_dir).as_posix(), "AES-256-CBC-MICRO", key.hex(), password=password)
    if results_rec:
        results_rec.record_finding(
            micro_file.relative_to(root_dir).as_posix(),
            "MICRO_ENCRYPTED_PAYLOAD_32B",
            "Category_C",
            "PASS",
            ["KINTSUGI_MAGIC_BYTE_01"],
            severity="PASS"
        )
    logger.info(f"[Category C - Heuristic 3] Created Micro Payload (32 bytes): {micro_file.relative_to(root_dir).as_posix()}")

def generate_category_d_compliance_violations(etc_dir: Path, audit_dir: Path, billing_dir: Path, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """
    Category D: Deliberate Insecure Configurations (Compliance Violations).
    - Permissive file permissions (0o777 on cleartext CSVs)
    - Transmission Protection: Insecure sshd_config (Protocol 1, weak ciphers)
    - Configuration Management: login.defs (PASS_MAX_DAYS 99999) & passwd (active shells for daemon/bin)
    - Audit Subsystem: audit.log left world-writable (0o666)
    """
    validate_path_in_scope(etc_dir, root_dir)
    validate_path_in_scope(audit_dir, root_dir)
    validate_path_in_scope(billing_dir, root_dir)

    etc_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)
    billing_dir.mkdir(parents=True, exist_ok=True)

    # 1. Access Control Violation (0o777 permissions on cleartext CSV with PANs)
    copay_file = billing_dir / "merchant_copay_ledger.csv"
    validate_path_in_scope(copay_file, root_dir)
    lines = ["copay_id,patient_name,pan_credit_card,amount,ssn\n"]
    for i in range(50):
        lines.append(f"{i+1},Copay_Patient_{i},{generate_luhn_pan()},{random.uniform(10, 200):.2f},{generate_ssn()}\n")
    with open(copay_file, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    safe_chmod(copay_file, 0o777)
    if results_rec:
        results_rec.record_finding(
            copay_file.relative_to(root_dir).as_posix(),
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_7_1", "HIPAA_164_312_a_1"],
            severity="CRITICAL",
            details={"permissions": "0777"}
        )
    logger.warning(f"[Category D - Access Violation] Injected 0o777 world-writable file: {copay_file.relative_to(root_dir).as_posix()}")

    # 2. Transmission Protection Violation (/etc/ssh/sshd_config)
    ssh_dir = etc_dir / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    sshd_config = ssh_dir / "sshd_config"
    validate_path_in_scope(sshd_config, root_dir)
    sshd_content = (
        "# MOCK INSECURE SSHD CONFIGURATION FOR COMPLIANCE TESTING\n"
        "Protocol 1\n"
        "Ciphers blowfish-cbc,3des-cbc,aes128-cbc\n"
        "MACs hmac-md5,hmac-sha1\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes\n"
    )
    with open(sshd_config, "w", encoding="utf-8") as f:
        f.write(sshd_content)
    if results_rec:
        results_rec.record_finding(
            sshd_config.relative_to(root_dir).as_posix(),
            "INSECURE_SSH_TRANSMISSION_PROTOCOL",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_2_2_4", "HITRUST_09_m"],
            severity="HIGH",
            details={"issues": ["Protocol 1", "Blowfish-CBC", "HMAC-MD5"]}
        )
    logger.warning(f"[Category D - Transmission Protection] Injected SSH Protocol 1 & weak ciphers: {sshd_config.relative_to(root_dir).as_posix()}")

    # 3. Configuration Management Violations (/etc/login.defs & /etc/passwd)
    login_defs = etc_dir / "login.defs"
    validate_path_in_scope(login_defs, root_dir)
    login_defs_content = (
        "PASS_MAX_DAYS 99999\n"
        "PASS_MIN_DAYS 0\n"
        "PASS_WARN_AGE 7\n"
    )
    with open(login_defs, "w", encoding="utf-8") as f:
        f.write(login_defs_content)
    if results_rec:
        results_rec.record_finding(
            login_defs.relative_to(root_dir).as_posix(),
            "INSECURE_PASSWORD_POLICY_MAX_DAYS",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_8_3_6", "HITRUST_10_j"],
            severity="MEDIUM",
            details={"PASS_MAX_DAYS": 99999}
        )
    logger.warning(f"[Category D - Config Management] Injected invalid PASS_MAX_DAYS 99999: {login_defs.relative_to(root_dir).as_posix()}")

    passwd_file = etc_dir / "passwd"
    validate_path_in_scope(passwd_file, root_dir)
    passwd_content = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"     # Violation: system account mapped to active shell
        "bin:x:2:2:bin:/bin:/bin/sh\n"                 # Violation: system account mapped to active shell
        "sys:x:3:3:sys:/dev:/bin/sh\n"                 # Violation
        "jsmith:x:1001:1001:Doctor Smith:/home/jsmith:/bin/bash\n"
    )
    with open(passwd_file, "w", encoding="utf-8") as f:
        f.write(passwd_content)
    if results_rec:
        results_rec.record_finding(
            passwd_file.relative_to(root_dir).as_posix(),
            "INSECURE_SYSTEM_ACCOUNT_HARDENING",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_8_2_1", "HIPAA_164_312_a_1"],
            severity="HIGH",
            details={"daemon_shell": "/bin/sh", "bin_shell": "/bin/sh"}
        )
    logger.warning(f"[Category D - Account Hardening] Injected active shells for system daemon/bin: {passwd_file.relative_to(root_dir).as_posix()}")

    group_file = etc_dir / "group"
    validate_path_in_scope(group_file, root_dir)
    with open(group_file, "w", encoding="utf-8") as f:
        f.write("root:x:0:\ndaemon:x:1:\nbin:x:2:\nmedical:x:1001:jsmith\n")

    # 4. Audit Subsystem Violation (/var/log/audit/audit.log)
    audit_log = audit_dir / "audit.log"
    validate_path_in_scope(audit_log, root_dir)
    audit_content = (
        "type=SYSCALL msg=audit(1723300000.100:1): arch=c000003e syscall=2 success=yes pid=1024 uid=0 auid=1001 euid=0 exe=\"/bin/cat\" key=\"audit_test\"\n"
    )
    with open(audit_log, "w", encoding="utf-8") as f:
        f.write(audit_content * 50)
    safe_chmod(audit_log, 0o666)
    if results_rec:
        results_rec.record_finding(
            audit_log.relative_to(root_dir).as_posix(),
            "INSECURE_AUDIT_LOG_PERMISSIONS",
            "Category_D",
            "FAIL",
            ["HIPAA_164_312_b", "PCI_DSS_v4_10_2_1"],
            severity="HIGH",
            details={"permissions": "0666"}
        )
    logger.warning(f"[Category D - Audit Subsystem] Injected 0o666 world-writable audit log: {audit_log.relative_to(root_dir).as_posix()}")

    # 5. Transmission Protection / System TLS Policy Violations (OpenSSL, Crypto-Policies, Nginx, Windows Schannel)
    ssl_dir = etc_dir / "ssl"
    ssl_dir.mkdir(parents=True, exist_ok=True)
    openssl_cnf = ssl_dir / "openssl.cnf"
    validate_path_in_scope(openssl_cnf, root_dir)
    openssl_content = (
        "# MOCK INSECURE SYSTEM OPENSSL TLS POLICY CONFIGURATION\n"
        "[openssl_init]\n"
        "ssl_conf = ssl_sect\n\n"
        "[ssl_sect]\n"
        "system_default = system_default_sect\n\n"
        "[system_default_sect]\n"
        "MinProtocol = TLSv1.0\n"
        "MaxProtocol = TLSv1.3\n"
        "CipherString = DEFAULT:@SECLEVEL=0:ALL:!aNULL:3DES:RC4\n"
    )
    with open(openssl_cnf, "w", encoding="utf-8") as f:
        f.write(openssl_content)

    crypto_pol_dir = etc_dir / "crypto-policies" / "state"
    crypto_pol_dir.mkdir(parents=True, exist_ok=True)
    crypto_state = crypto_pol_dir / "current"
    validate_path_in_scope(crypto_state, root_dir)
    with open(crypto_state, "w", encoding="utf-8") as f:
        f.write("LEGACY\n")  # RHEL/Fedora LEGACY policy allows TLS 1.0/1.1

    nginx_dir = etc_dir / "nginx" / "conf.d"
    nginx_dir.mkdir(parents=True, exist_ok=True)
    nginx_ssl = nginx_dir / "ssl_policy.conf"
    validate_path_in_scope(nginx_ssl, root_dir)
    nginx_ssl_content = (
        "# MOCK INSECURE WEBSERVER TLS POLICY CONFIGURATION\n"
        "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        "ssl_ciphers \"ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RC4:3DES:DES-CBC3-SHA\";\n"
        "ssl_prefer_server_ciphers off;\n"
    )
    with open(nginx_ssl, "w", encoding="utf-8") as f:
        f.write(nginx_ssl_content)

    # Windows Schannel TLS Registry Export Mock
    reg_dir = etc_dir / "registry"
    reg_dir.mkdir(parents=True, exist_ok=True)
    schannel_reg = reg_dir / "hklm_schannel_export.reg"
    validate_path_in_scope(schannel_reg, root_dir)
    schannel_reg_content = (
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server]\n"
        "\"Enabled\"=dword:00000001\n"
        "\"DisabledByDefault\"=dword:00000000\n\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server]\n"
        "\"Enabled\"=dword:00000001\n"
        "\"DisabledByDefault\"=dword:00000000\n\n"
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\RC4 128/128]\n"
        "\"Enabled\"=dword:00000001\n"
    )
    with open(schannel_reg, "w", encoding="utf-8") as f:
        f.write(schannel_reg_content)

    sec_dir = etc_dir / "security"
    sec_dir.mkdir(parents=True, exist_ok=True)
    schannel_json = sec_dir / "schannel_tls_policy.json"
    validate_path_in_scope(schannel_json, root_dir)
    with open(schannel_json, "w", encoding="utf-8") as f:
        json.dump({
            "system_policy": "Windows Schannel Security Provider",
            "protocols": {
                "SSL 3.0": {"ServerEnabled": 1},
                "TLS 1.0": {"ServerEnabled": 1},
                "TLS 1.1": {"ServerEnabled": 1},
                "TLS 1.2": {"ServerEnabled": 1}
            },
            "ciphers": {
                "RC4 128/128": {"Enabled": 1},
                "Triple DES 168": {"Enabled": 1}
            }
        }, f, indent=2)

    if results_rec:
        results_rec.record_finding(
            openssl_cnf.relative_to(root_dir).as_posix(),
            "INSECURE_SYSTEM_TLS_POLICY",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_4_2_1", "HIPAA_164_312_e_1"],
            severity="HIGH",
            details={"MinProtocol": "TLSv1.0", "SECLEVEL": 0}
        )

    logger.warning(f"[Category D - TLS Policy] Injected mock system TLS policy configurations: {openssl_cnf.relative_to(root_dir).as_posix()}, {nginx_ssl.relative_to(root_dir).as_posix()}, {schannel_reg.relative_to(root_dir).as_posix()}")

# -----------------------------------------------------------------------------
# ADDITIONAL SPECIALIZED PAYLOADS (IMAGES, AES-ECB, ZIP BOMB)
# -----------------------------------------------------------------------------
def generate_mock_images(target_dir: Path, root_dir: Path):
    """Generates mock radiology/promo binary images (PNG/JPEG headers + random high entropy stream)."""
    validate_path_in_scope(target_dir, root_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    png_path = target_dir / "chest_xray_20260810_001.png"
    jpg_path = target_dir / "brain_mri_patient_9021.jpg"

    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00"
    png_payload = png_header + secrets.token_bytes(128 * 1024)

    jpg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    jpg_payload = jpg_header + secrets.token_bytes(128 * 1024)

    with open(png_path, "wb") as f:
        f.write(png_payload)
    with open(jpg_path, "wb") as f:
        f.write(jpg_payload)

    logger.info(f"Generated mock radiology image binaries: {png_path.relative_to(root_dir).as_posix()}, {jpg_path.relative_to(root_dir).as_posix()}")

def generate_insecure_aes_ecb_ledger(file_path: Path, password: str, key_mgr: KeyManager, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """Generates an insecure AES-256-ECB encrypted file (block pattern leakage test)."""
    validate_path_in_scope(file_path, root_dir)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Repeating 16-byte blocks result in identical 16-byte ciphertext blocks in ECB mode!
    repeated_block = b"BALANCE_00000000" * 200  # Exact 16-byte block repeated
    key = derive_key(password)
    ciphertext = encrypt_aes_256_ecb(repeated_block, key)

    with open(file_path, "wb") as f:
        f.write(ciphertext)

    key_mgr.record_key(file_path.relative_to(root_dir).as_posix(), "AES-256-ECB", key.hex(), password=password)
    if results_rec:
        results_rec.record_finding(
            file_path.relative_to(root_dir).as_posix(),
            "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_3_5", "NIST_SP800_38A"],
            severity="HIGH"
        )
    logger.warning(f"Injected insecure AES-256-ECB database (block pattern leak): {file_path.relative_to(root_dir).as_posix()}")

def generate_zip_bomb(file_path: Path, root_dir: Path, results_rec: ExpectedResultsRecorder = None):
    """Generates a safe Zip Bomb test file (tiny ZIP expanding to 10MB of null bytes)."""
    validate_path_in_scope(file_path, root_dir)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # 10 MB of repeated zeros
    uncompressed_10mb = b"\x00" * (10 * 1024 * 1024)
    with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("null_stream_10mb.raw", uncompressed_10mb)

    if results_rec:
        results_rec.record_finding(
            file_path.relative_to(root_dir).as_posix(),
            "DECOMPRESSION_SAFETY_BOMB_TEST",
            "Category_B",
            "WARNING",
            ["KINTSUGI_SAFETY_DECOMPRESSION_01"],
            severity="MEDIUM",
            details={"uncompressed_bytes": 10485760}
        )
    logger.warning(f"[Safety Test] Generated Zip Bomb test file ({file_path.stat().st_size} bytes -> 10MB): {file_path.relative_to(root_dir).as_posix()}")

# -----------------------------------------------------------------------------
# INDUSTRY ENVIRONMENT BUILDERS
# -----------------------------------------------------------------------------
def build_healthcare_environment(base_dir: Path, key_mgr: KeyManager, results_rec: ExpectedResultsRecorder = None):
    env_root = base_dir / "healthcare_production_env"
    env_root.mkdir(parents=True, exist_ok=True)

    logger.info(f"--- Constructing Healthcare Environment: {env_root.resolve().as_posix()} ---")

    # Patient records
    generate_category_a_compliant_encrypted(
        env_root / "patient_records" / "ehr_db_master.gpg",
        "HealthCareSecurePass2026!",
        1500, key_mgr, env_root, results_rec
    )
    generate_category_c_false_negatives(env_root / "patient_records", "HealthCareSecurePass2026!", key_mgr, env_root, results_rec)
    generate_mock_images(env_root / "radiology_images", env_root)

    # Billing & Copay
    billing_dir = env_root / "billing_department"
    billing_dir.mkdir(parents=True, exist_ok=True)

    claims_csv = billing_dir / "claims_export_2026_q2.csv"
    validate_path_in_scope(claims_csv, env_root)
    claims_lines = ["claim_id,patient_ssn,pan_card,icd10_code,claim_amount\n"]
    for i in range(100):
        claims_lines.append(f"CLM_{i+100},{generate_ssn()},{generate_luhn_pan()},E11.9,{random.uniform(100, 5000):.2f}\n")
    with open(claims_csv, "w", encoding="utf-8") as f:
        f.write("".join(claims_lines))
    if results_rec:
        results_rec.record_finding(
            claims_csv.relative_to(env_root).as_posix(),
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN",
            "Category_D",
            "FAIL",
            ["HIPAA_164_312_e_1", "PCI_DSS_v4_4_2_1"],
            severity="CRITICAL",
            details={"findings": ["SSN", "LUHN_PAN", "ICD10"]}
        )

    # Internal policies
    policies_dir = env_root / "internal_policies"
    validate_path_in_scope(policies_dir, env_root)
    policies_dir.mkdir(parents=True, exist_ok=True)
    with open(policies_dir / "hipaa_safeguards_policy_v4.txt", "w", encoding="utf-8") as f:
        f.write("HIPAA Technical Safeguards (§164.312) Corporate Policy\nAll PHI must be encrypted at rest.\n")

    # Insecure configurations & AD exports
    etc_dir = env_root / "etc"
    audit_dir = env_root / "var" / "log" / "audit"
    generate_category_d_compliance_violations(etc_dir, audit_dir, billing_dir, env_root, results_rec)
    generate_active_directory_exports(etc_dir, key_mgr, env_root)

def build_merchant_environment(base_dir: Path, key_mgr: KeyManager, results_rec: ExpectedResultsRecorder = None):
    env_root = base_dir / "merchant_production_env"
    env_root.mkdir(parents=True, exist_ok=True)

    logger.info(f"--- Constructing Merchant Environment: {env_root.resolve().as_posix()} ---")

    # Point of Sale
    pos_dir = env_root / "point_of_sale"
    pos_dir.mkdir(parents=True, exist_ok=True)

    generate_category_a_compliant_encrypted(
        pos_dir / "daily_pos_settlement_20260810.db",
        "MerchantPOSSecretKey2026!",
        1000, key_mgr, env_root, results_rec
    )

    # Insecure POS terminal debug log with cleartext PANs
    debug_log = pos_dir / "terminal_buffer_debug.log"
    validate_path_in_scope(debug_log, env_root)
    log_lines = [f"[DEBUG] POS_TRANS_ID={i} CARD={generate_luhn_pan()} TRACK2=4111111111111111=2612101000\n" for i in range(100)]
    with open(debug_log, "w", encoding="utf-8") as f:
        f.write("".join(log_lines))
    safe_chmod(debug_log, 0o777)
    if results_rec:
        results_rec.record_finding(
            debug_log.relative_to(env_root).as_posix(),
            "PERMISSIVE_ACCESS_CONTROL_CLEARTEXT_PAN",
            "Category_D",
            "FAIL",
            ["PCI_DSS_v4_7_1", "PCI_DSS_v4_3_4"],
            severity="CRITICAL"
        )

    # E-Commerce Backend & ASCII Armored API config
    ecom_dir = env_root / "e_commerce_backend"
    validate_path_in_scope(ecom_dir, env_root)
    ecom_dir.mkdir(parents=True, exist_ok=True)
    gw_config = ecom_dir / "payment_gateway_config.json"
    priv_ssh, pub_ssh = generate_mock_ssh_keypair()
    with open(gw_config, "w", encoding="utf-8") as f:
        f.write(json.dumps({"merchant_id": "M_88201", "api_ssh_private_key": priv_ssh}, indent=2))
    key_mgr.record_key(gw_config.relative_to(env_root).as_posix(), "RSA-MOCK-SSH", key_hex="N/A", extra={"ssh_pub": pub_ssh})

    # Inventory & False Positive ZIP
    generate_category_b_false_positives(env_root / "inventory_control", env_root, results_rec)

    # Marketing assets
    generate_mock_images(env_root / "marketing_assets", env_root)

    # Insecure configurations & AD exports
    etc_dir = env_root / "etc"
    audit_dir = env_root / "var" / "log" / "audit"
    generate_category_d_compliance_violations(etc_dir, audit_dir, pos_dir, env_root, results_rec)
    generate_active_directory_exports(etc_dir, key_mgr, env_root)

def build_finance_environment(base_dir: Path, key_mgr: KeyManager, results_rec: ExpectedResultsRecorder = None):
    env_root = base_dir / "finance_production_env"
    env_root.mkdir(parents=True, exist_ok=True)

    logger.info(f"--- Constructing Finance Environment: {env_root.resolve().as_posix()} ---")

    # Wire transfers
    wire_dir = env_root / "wire_transfers"
    wire_dir.mkdir(parents=True, exist_ok=True)
    generate_category_a_compliant_encrypted(
        wire_dir / "swift_wire_batch_20260810.dat",
        "FinanceWireTransferSecret!",
        800, key_mgr, env_root, results_rec
    )

    # AES-ECB block pattern leak
    generate_insecure_aes_ecb_ledger(
        wire_dir / "ach_settlement_log.csv",
        "FinanceWireTransferSecret!",
        key_mgr, env_root, results_rec
    )

    # Core ledger & Treasury ops
    generate_category_c_false_negatives(env_root / "treasury_ops", "FinanceWireTransferSecret!", key_mgr, env_root, results_rec)

    # Backups & Zip Bomb safety test
    backups_dir = env_root / "system_backups"
    generate_category_b_false_positives(backups_dir, env_root, results_rec)
    generate_zip_bomb(backups_dir / "decompression_safety_check.zip", env_root, results_rec)

    # Insecure configurations & AD exports
    etc_dir = env_root / "etc"
    audit_dir = env_root / "var" / "log" / "audit"
    core_ledger_dir = env_root / "core_ledger"
    core_ledger_dir.mkdir(parents=True, exist_ok=True)
    generate_category_d_compliance_violations(etc_dir, audit_dir, core_ledger_dir, env_root, results_rec)
    generate_active_directory_exports(etc_dir, key_mgr, env_root)

def build_banking_environment(base_dir: Path, key_mgr: KeyManager, results_rec: ExpectedResultsRecorder = None):
    env_root = base_dir / "banking_production_env"
    env_root.mkdir(parents=True, exist_ok=True)

    logger.info(f"--- Constructing Banking Environment: {env_root.resolve().as_posix()} ---")

    wire_dir = env_root / "wire_transfers"
    wire_dir.mkdir(parents=True, exist_ok=True)
    generate_category_a_compliant_encrypted(
        wire_dir / "swift_wire_batch_20260810.dat",
        "BankingSecretPass2026!",
        1200, key_mgr, env_root, results_rec
    )
    generate_insecure_aes_ecb_ledger(
        wire_dir / "ach_settlement_log.csv",
        "BankingSecretPass2026!",
        key_mgr, env_root, results_rec
    )

    generate_category_c_false_negatives(env_root / "treasury_ops", "BankingSecretPass2026!", key_mgr, env_root, results_rec)

    backups_dir = env_root / "system_backups"
    generate_category_b_false_positives(backups_dir, env_root, results_rec)
    generate_zip_bomb(backups_dir / "decompression_safety_check.zip", env_root, results_rec)

    etc_dir = env_root / "etc"
    audit_dir = env_root / "var" / "log" / "audit"
    core_ledger_dir = env_root / "core_ledger"
    core_ledger_dir.mkdir(parents=True, exist_ok=True)
    generate_category_d_compliance_violations(etc_dir, audit_dir, core_ledger_dir, env_root, results_rec)
    generate_active_directory_exports(etc_dir, key_mgr, env_root)

# -----------------------------------------------------------------------------
# MAIN CLI ENTRYPOINT
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Production-Grade Synthetic Production Environment Generator for Kintsugi-GRC."
    )
    parser.add_argument(
        "--industry",
        choices=["healthcare", "merchant", "finance", "banking", "all"],
        default="all",
        help="Target industry environment to generate (default: all)."
    )
    parser.add_argument(
        "--output-dir",
        default="./synthetic_test_env",
        help="Target root directory where synthetic environments will be created (default: ./synthetic_test_env)."
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional seed value for reproducible synthetic generation."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose DEBUG logging."
    )

    args = parser.parse_args()

    output_base = Path(args.output_dir).resolve()
    output_base.mkdir(parents=True, exist_ok=True)

    setup_logging(output_base=output_base, verbose=args.verbose)

    if args.seed is not None:
        random.seed(args.seed)
        logger.info(f"Seeded random generator with seed={args.seed}")

    logger.info(f"Starting Kintsugi-GRC Synthetic Generator (Python {sys.version.split()[0]})")
    logger.info(f"Target Output Directory: {output_base.as_posix()}")

    key_mgr = KeyManager(output_base)
    key_mgr.initialize()

    results_rec = ExpectedResultsRecorder(output_base)

    industries = [args.industry] if args.industry != "all" else ["healthcare", "merchant", "finance", "banking"]

    if "healthcare" in industries:
        build_healthcare_environment(output_base, key_mgr, results_rec)
    if "merchant" in industries:
        build_merchant_environment(output_base, key_mgr, results_rec)
    if "finance" in industries:
        build_finance_environment(output_base, key_mgr, results_rec)
    if "banking" in industries:
        build_banking_environment(output_base, key_mgr, results_rec)

    key_mgr.save()
    results_rec.save()

    # Save backup of audit log inside .keys/
    audit_log_src = output_base / "synthetic_generation_audit.log"
    audit_log_bak = output_base / ".keys" / "synthetic_generation_audit.bak"
    if audit_log_src.exists():
        shutil.copy2(audit_log_src, audit_log_bak)
        safe_chmod(audit_log_bak, 0o600)

    logger.info(f"Successfully completed synthetic environment generation. Audit log saved to {audit_log_src.relative_to(output_base).as_posix()}")

if __name__ == "__main__":
    main()
