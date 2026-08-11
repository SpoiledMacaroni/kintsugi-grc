"""
Kintsugi-GRC Framework Control Mapper
Reads and parses grc_controls.zip to map technical scan findings to GRC Framework controls:
- HITRUST CSF v11.8.0
- PCI DSS v4.0.1
- HIPAA Security Rule (45 CFR §164.312)
- NIST SP 800-53 Rev 5
- NIST Cybersecurity Framework 2.0 (NIST CSF)
"""

import json
import logging
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kintsugi_scanner")

class ControlRegistry:
    """Manages loaded GRC framework controls and maps technical finding rule IDs to framework citations."""
    def __init__(self, zip_path: Path = Path("grc_controls.zip")):
        self.zip_path = zip_path
        self.frameworks: Dict[str, Any] = {}
        self.hitrust_domains: List[Dict[str, Any]] = []
        self.loaded = False

    def load(self) -> bool:
        """Loads and parses all JSON framework mapping schemas inside grc_controls.zip."""
        if not self.zip_path.exists():
            logger.warning(f"Control schema archive not found at {self.zip_path.as_posix()}. Running with fallback rule maps.")
            return False

        try:
            with zipfile.ZipFile(self.zip_path, "r") as z:
                for name in z.namelist():
                    if name.endswith(".json"):
                        content = json.loads(z.read(name).decode("utf-8"))
                        if name == "kintsugi_grc_control_clauses.json":
                            self.hitrust_domains = content.get("hitrust_domains", [])
                        else:
                            fw_name = content.get("framework", name)
                            self.frameworks[fw_name] = content

            self.loaded = True
            logger.info(f"Successfully loaded GRC control schema from {self.zip_path.name} ({len(self.frameworks)} frameworks)")
            return True
        except Exception as e:
            logger.error(f"Failed to load control schema archive {self.zip_path.as_posix()}: {e}")
            return False

    def map_rule_to_frameworks(self, rule_id: str, default_rule_ids: List[str] = None) -> List[Dict[str, Any]]:
        """Maps a technical rule ID (e.g. PERMISSIVE_ACCESS_CONTROL, UNENCRYPTED_SENSITIVE_DATA) to GRC controls."""
        citations = []
        
        # Rule mapping database
        rule_mappings = {
            "ENCRYPTED_COMPLIANT_AES_256_CBC": [
                {"framework": "HIPAA", "control_id": "164.312(a)(2)(iv)", "title": "Encryption and decryption", "status": "COMPLIANT"},
                {"framework": "PCI DSS", "control_id": "Requirement 3.5", "title": "Document and implement procedures to protect stored PAN", "status": "COMPLIANT"},
                {"framework": "HITRUST CSF", "control_id": "Domain 09", "title": "Transmission Protection & Data Encryption at Rest", "status": "COMPLIANT"},
                {"framework": "NIST 800-53", "control_id": "SC-13", "title": "Cryptographic Protection", "status": "COMPLIANT"},
                {"framework": "NIST CSF", "control_id": "PR.DS-01", "title": "Data-at-rest is protected", "status": "COMPLIANT"}
            ],
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": [
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Technical Safeguards - Transmission security", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 4.2", "title": "PAN transmitted electronically must be encrypted", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Domain 09", "title": "Data Protection & Encryption Requirements", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-8", "title": "Transmission Confidentiality and Integrity", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.DS-02", "title": "Data-in-transit is protected", "status": "VIOLATION"}
            ],
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": [
                {"framework": "PCI DSS", "control_id": "Requirement 7.1", "title": "Restrict access to system components to least privilege", "status": "VIOLATION"},
                {"framework": "HIPAA", "control_id": "164.312(a)(1)", "title": "Access control - Minimum Necessary", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Domain 01", "title": "Access Control & Least Privilege Management", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AC-6", "title": "Least Privilege", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.AA-05", "title": "Access permissions are managed according to least privilege", "status": "VIOLATION"}
            ],
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": [
                {"framework": "PCI DSS", "control_id": "Requirement 2.2.4", "title": "Insecure management protocols must be disabled", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Domain 09.m", "title": "Network Security & Protocol Hardening", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "CM-6", "title": "Configuration Settings", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.PS-01", "title": "Configuration management practices applied", "status": "VIOLATION"}
            ],
            "INSECURE_SYSTEM_TLS_POLICY": [
                {"framework": "PCI DSS", "control_id": "Requirement 4.2.1", "title": "Strong cryptography for transmission of cardholder data", "status": "VIOLATION"},
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Transmission security - Strong TLS Policy", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Domain 09.v", "title": "Secure TLS Communication Protocols", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-8(1)", "title": "Cryptographic Protection of Transmitted Information", "status": "VIOLATION"}
            ],
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": [
                {"framework": "PCI DSS", "control_id": "Requirement 8.3.6", "title": "Password expiry & rotation policy enforcement", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Domain 10.j", "title": "Password Management Policy", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "IA-5(1)", "title": "Password-Based Authentication", "status": "VIOLATION"}
            ],
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": [
                {"framework": "PCI DSS", "control_id": "Requirement 8.2.1", "title": "Remove or disable unnecessary default accounts", "status": "VIOLATION"},
                {"framework": "HIPAA", "control_id": "164.312(a)(1)", "title": "Unique user identification & account hardening", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AC-2", "title": "Account Management", "status": "VIOLATION"}
            ],
            "INSECURE_AUDIT_LOG_PERMISSIONS": [
                {"framework": "HIPAA", "control_id": "164.312(b)", "title": "Audit controls - Log Tamper Protection", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 10.2.1", "title": "Audit log protection against unauthorized modification", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AU-9", "title": "Protection of Audit Information", "status": "VIOLATION"}
            ],
            "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK": [
                {"framework": "PCI DSS", "control_id": "Requirement 3.5", "title": "Use strong approved cryptographic modes (avoid ECB)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-13", "title": "Cryptographic Protection (NIST SP 800-38A)", "status": "VIOLATION"}
            ],
            "DECOMPRESSION_SAFETY_BOMB_TEST": [
                {"framework": "NIST CSF", "control_id": "DE.AE-01", "title": "Anomalous patterns & safety boundaries", "status": "WARNING"},
                {"framework": "KINTSUGI_SAFETY", "control_id": "SAFETY-01", "title": "Resource exhaustion & decompression bomb guardrail", "status": "WARNING"}
            ]
        }

        if rule_id in rule_mappings:
            return rule_mappings[rule_id]

        if default_rule_ids:
            for rid in default_rule_ids:
                if rid in rule_mappings:
                    return rule_mappings[rid]
                citations.append({"framework": "GENERAL_GRC", "control_id": rid, "title": "Compliance Rule Requirement", "status": "REVIEW"})
            return citations

        return [{"framework": "GENERAL_GRC", "control_id": rule_id, "title": "Custom Technical Security Requirement", "status": "REVIEW"}]
