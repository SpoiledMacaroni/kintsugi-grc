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

    def map_rule_to_frameworks(self, rule_id: str, default_rule_ids: List[str] = None, industry: str = "All Industries") -> List[Dict[str, Any]]:
        """Maps a technical rule ID to GRC controls, strictly filtered by target industry."""
        # Industry-to-Framework Assignments (Strict isolation when industry != All)
        industry_frameworks = {
            "Healthcare": ["HIPAA"],
            "Merchant / E-Commerce": ["PCI DSS"],
            "Merchant": ["PCI DSS"],
            "Finance / Treasury": ["NIST 800-53"],
            "Finance": ["NIST 800-53"],
            "Banking / SWIFT": ["PCI DSS", "NIST 800-53"],
            "Banking": ["PCI DSS", "NIST 800-53"]
        }
        
        # Comprehensive Rule Mapping Registry (Coverage for HIPAA, PCI DSS, NIST 800-53, HITRUST CSF, NIST CSF)
        rule_mappings = {
            "COMPLIANT_SECURITY_BASELINE": [
                {"framework": "HIPAA", "control_id": "164.312(a)(1)", "title": "Technical Safeguards - Compliant Security Baseline", "status": "COMPLIANT"},
                {"framework": "PCI DSS", "control_id": "Requirement 2.2", "title": "System components configured to baseline standards", "status": "COMPLIANT"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.m (09.04)", "title": "Configuration Management & Baseline Security", "status": "COMPLIANT"},
                {"framework": "NIST 800-53", "control_id": "CM-6", "title": "Configuration Settings Baseline", "status": "COMPLIANT"},
                {"framework": "NIST CSF", "control_id": "PR.PS-01", "title": "Configuration management baseline applied", "status": "COMPLIANT"}
            ],
            "ENCRYPTED_COMPLIANT_AES_256_CBC": [
                {"framework": "HIPAA", "control_id": "164.312(a)(2)(iv)", "title": "Encryption and decryption safeguards", "status": "COMPLIANT"},
                {"framework": "PCI DSS", "control_id": "Requirement 3.5", "title": "Document and implement procedures to protect stored PAN", "status": "COMPLIANT"},
                {"framework": "HITRUST CSF", "control_id": "Ref 06.d (06.01)", "title": "Data Protection and Privacy (Compliant AES-256)", "status": "COMPLIANT"},
                {"framework": "NIST 800-53", "control_id": "SC-13", "title": "Cryptographic Protection", "status": "COMPLIANT"},
                {"framework": "NIST CSF", "control_id": "PR.DS-01", "title": "Data-at-rest is protected", "status": "COMPLIANT"}
            ],
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": [
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Technical Safeguards - Transmission security & unencrypted data", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 4.2", "title": "PAN transmitted electronically must be encrypted", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 06.d (06.01)", "title": "Data Protection and Privacy (Cleartext PII/PHI Exposed)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-8", "title": "Transmission Confidentiality and Integrity", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.DS-02", "title": "Data-in-transit is protected", "status": "VIOLATION"}
            ],
            "UNENCRYPTED_RAW_ZLIB_STREAM": [
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Technical Safeguards - Raw compressed unencrypted stream", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 4.2", "title": "Unencrypted compressed payloads violate cardholder security", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.q (09.07)", "title": "Information Handling Procedures (Raw Compressed Stream)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-8", "title": "Transmission Confidentiality and Integrity", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.DS-02", "title": "Data-in-transit is protected", "status": "VIOLATION"}
            ],
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": [
                {"framework": "HIPAA", "control_id": "164.312(a)(1)", "title": "Access control - Minimum Necessary & Least Privilege", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 7.1", "title": "Restrict access to system components to least privilege", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.m (09.04)", "title": "System Configuration & Baseline Permissions", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AC-6", "title": "Least Privilege", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.AA-05", "title": "Access permissions managed according to least privilege", "status": "VIOLATION"}
            ],
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": [
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Technical Safeguards - Insecure management transmission protocols", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 2.2.4", "title": "Insecure management protocols must be disabled", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 10.m (10.06)", "title": "Control of Technical Vulnerabilities (SSH Protocol 1 / Ciphers)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "CM-6", "title": "Configuration Settings", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.PS-01", "title": "Configuration management practices applied", "status": "VIOLATION"}
            ],
            "INSECURE_SYSTEM_TLS_POLICY": [
                {"framework": "HIPAA", "control_id": "164.312(e)(1)", "title": "Transmission security - Strong TLS Policy enforcement", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 4.2.1", "title": "Strong cryptography for transmission of cardholder data", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 10.m (10.06)", "title": "Control of Technical Vulnerabilities (Deprecated TLS 1.0/1.1)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-8(1)", "title": "Cryptographic Protection of Transmitted Information", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.DS-02", "title": "Protections for data in transit", "status": "VIOLATION"}
            ],
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": [
                {"framework": "HIPAA", "control_id": "164.312(a)(2)(i)", "title": "Access Control - Automatic logoff & password expiry policy", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 8.3.6", "title": "Password expiry & rotation policy enforcement", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 10.m (10.06)", "title": "Control of Technical Vulnerabilities (PASS_MAX_DAYS > 90)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "IA-5(1)", "title": "Password-Based Authentication", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.AA-01", "title": "Identities and credentials managed", "status": "VIOLATION"}
            ],
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": [
                {"framework": "HIPAA", "control_id": "164.312(a)(1)", "title": "Unique user identification & default account hardening", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 8.2.1", "title": "Remove or disable unnecessary default accounts", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 10.m (10.06)", "title": "Control of Technical Vulnerabilities (Active Shells on Daemon Accounts)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AC-2", "title": "Account Management", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.AA-02", "title": "Identities authenticated", "status": "VIOLATION"}
            ],
            "INSECURE_AUDIT_LOG_PERMISSIONS": [
                {"framework": "HIPAA", "control_id": "164.312(b)", "title": "Audit controls - Log Tamper Protection & Integrity", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 10.2.1", "title": "Audit log protection against unauthorized modification", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.aa (09.10)", "title": "Monitoring / Audit Logging (World-Writable /var/log/audit)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "AU-9", "title": "Protection of Audit Information", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.PT-01", "title": "Audit logs are protected", "status": "VIOLATION"}
            ],
            "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK": [
                {"framework": "HIPAA", "control_id": "164.312(a)(2)(iv)", "title": "Encryption Safeguards - Avoid insecure cipher modes (ECB)", "status": "VIOLATION"},
                {"framework": "PCI DSS", "control_id": "Requirement 3.5", "title": "Use strong approved cryptographic modes (avoid ECB)", "status": "VIOLATION"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.q (09.07)", "title": "Information Handling Procedures (Insecure AES-ECB Pattern Leak)", "status": "VIOLATION"},
                {"framework": "NIST 800-53", "control_id": "SC-13", "title": "Cryptographic Protection (NIST SP 800-38A)", "status": "VIOLATION"},
                {"framework": "NIST CSF", "control_id": "PR.DS-01", "title": "Data-at-rest cryptographic integrity", "status": "VIOLATION"}
            ],
            "DECOMPRESSION_SAFETY_BOMB_TEST": [
                {"framework": "HIPAA", "control_id": "164.312(c)(1)", "title": "Data Integrity & Denial of Service Safeguards", "status": "WARNING"},
                {"framework": "PCI DSS", "control_id": "Requirement 10.6", "title": "Review logs and anomalous safety events", "status": "WARNING"},
                {"framework": "HITRUST CSF", "control_id": "Ref 09.q (09.07)", "title": "Information Handling Procedures (Decompression Safety Boundary)", "status": "WARNING"},
                {"framework": "NIST 800-53", "control_id": "SI-4", "title": "System Monitoring & Boundary Safety", "status": "WARNING"},
                {"framework": "NIST CSF", "control_id": "DE.AE-01", "title": "Anomalous patterns & safety boundaries", "status": "WARNING"},
                {"framework": "KINTSUGI_SAFETY", "control_id": "SAFETY-01", "title": "Resource exhaustion & decompression bomb guardrail", "status": "WARNING"}
            ]
        }

        raw_citations = []
        if rule_id in rule_mappings:
            raw_citations = rule_mappings[rule_id]
        elif default_rule_ids:
            for rid in default_rule_ids:
                if rid in rule_mappings:
                    raw_citations.extend(rule_mappings[rid])
                else:
                    raw_citations.append({"framework": "GENERAL_GRC", "control_id": rid, "title": "Compliance Rule Requirement", "status": "REVIEW"})
        else:
            raw_citations = [{"framework": "GENERAL_GRC", "control_id": rule_id, "title": "Custom Technical Security Requirement", "status": "REVIEW"}]

        allowed_fws = industry_frameworks.get(industry)
        if allowed_fws:
            filtered = [c for c in raw_citations if c.get("framework") in allowed_fws]
            if filtered:
                return filtered
            # Synthesize industry-specific citation fallback if rule is custom
            primary_fw = allowed_fws[0]
            return [{
                "framework": primary_fw,
                "control_id": "164.312(e)(1)" if primary_fw == "HIPAA" else ("Requirement 2.2.4" if primary_fw == "PCI DSS" else "CM-6"),
                "title": f"{industry} Regulatory Security Baseline",
                "status": "VIOLATION" if "INSECURE" in rule_id or "UNENCRYPTED" in rule_id else "COMPLIANT"
            }]

        return raw_citations
