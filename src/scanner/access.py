"""
Kintsugi-GRC IAM & Access Control Auditor
Audits POSIX permission bitmasks, owner UIDs/GIDs, and cross-references 
Active Directory exports (ad_users_export.csv & ad_sid_uid_map.json) 
against Least Privilege access control policies.
"""

import csv
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("kintsugi_scanner")

class IAMAuditor:
    """Audits file access permissions and Active Directory user identities."""
    def __init__(self, target_root: Path):
        self.target_root = target_root
        self.users_by_uid: Dict[str, Dict[str, Any]] = {}
        self.users_by_sid: Dict[str, Dict[str, Any]] = {}
        self.loaded_ad = False

    def load_active_directory_maps(self) -> bool:
        """Locates and parses Active Directory exports within the target directory."""
        ad_csv = None
        ad_json = None

        # Search target root for etc/ad/ directory exports
        for root, _, files in os.walk(self.target_root):
            for file in files:
                if file == "ad_users_export.csv":
                    ad_csv = Path(root) / file
                elif file == "ad_sid_uid_map.json":
                    ad_json = Path(root) / file

        if ad_json and ad_json.exists():
            try:
                with open(ad_json, "r", encoding="utf-8") as f:
                    map_data = json.load(f)
                    mappings = map_data.get("identity_mappings", {})
                    for sid, details in mappings.items():
                        uid = str(details.get("uidNumber"))
                        self.users_by_sid[sid] = details
                        if uid:
                            self.users_by_uid[uid] = details
                self.loaded_ad = True
            except Exception as e:
                logger.warning(f"Failed to parse AD SID map {ad_json.as_posix()}: {e}")

        if ad_csv and ad_csv.exists():
            try:
                with open(ad_csv, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        uid = str(row.get("uidNumber"))
                        sid = row.get("objectSid")
                        if uid and uid not in self.users_by_uid:
                            self.users_by_uid[uid] = row
                        if sid and sid not in self.users_by_sid:
                            self.users_by_sid[sid] = row
                self.loaded_ad = True
            except Exception as e:
                logger.warning(f"Failed to parse AD CSV export {ad_csv.as_posix()}: {e}")

        if self.loaded_ad:
            logger.info(f"Loaded {len(self.users_by_uid)} Active Directory user identity mappings from target environment.")
        return self.loaded_ad

    def audit_file_permissions(self, file_path: Path) -> List[Dict[str, Any]]:
        """Audits file POSIX permissions and owner identity against Least Privilege rules."""
        findings = []
        try:
            stat_info = file_path.stat()
            mode = stat_info.st_mode
            mode_octal = oct(mode & 0o777)
            uid = str(stat_info.st_uid)

            # Rule 1: World-Writable Access Violation (0o777)
            if (mode & 0o002) != 0 and mode_octal == "0o777":
                findings.append({
                    "rule_id": "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE",
                    "title": "Permissive Access Control (0o777 World-Writable)",
                    "severity": "CRITICAL",
                    "description": f"File permissions '{mode_octal}' allow global write access to sensitive payload.",
                    "details": {"mode": mode_octal, "uid": uid}
                })

            # Rule 2: World-Writable Audit Subsystem Log (0o666 on audit.log)
            if file_path.name == "audit.log" and (mode & 0o002) != 0:
                findings.append({
                    "rule_id": "INSECURE_AUDIT_LOG_PERMISSIONS",
                    "title": "Audit Log World-Writable Permission",
                    "severity": "HIGH",
                    "description": f"Audit subsystem log '{file_path.name}' permissions '{mode_octal}' allow non-privileged tamper.",
                    "details": {"mode": mode_octal}
                })

            # Rule 3: Disabled or Orphaned Active Directory Account Access
            if self.loaded_ad and uid in self.users_by_uid:
                user_info = self.users_by_uid[uid]
                uac = str(user_info.get("userAccountControl", "512"))
                sam_account = user_info.get("sAMAccountName", f"uid_{uid}")
                if uac == "514":  # AD Account Disabled
                    findings.append({
                        "rule_id": "DISABLED_ACCOUNT_ACCESS_VIOLATION",
                        "title": "File Access Assigned to Disabled Active Directory Identity",
                        "severity": "HIGH",
                        "description": f"File is owned by disabled AD user '{sam_account}' (userAccountControl=514).",
                        "details": {"username": sam_account, "uid": uid, "userAccountControl": uac}
                    })

        except Exception as e:
            logger.debug(f"Could not stat permissions for {file_path.as_posix()}: {e}")

        return findings
