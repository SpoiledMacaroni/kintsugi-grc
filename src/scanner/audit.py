"""
Kintsugi-GRC Scanner Operation Audit Logger
Records every file access event, directory traversal, heuristic rule evaluation, 
Active Directory IAM lookup, and report file write to kintsugi_scanner_audit.log.
"""

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kintsugi_scanner_audit")

class ScannerAuditLogger:
    """Real-time operation audit logger recording all scanner actions."""
    def __init__(self, log_path: Path = Path("kintsugi_scanner_audit.log")):
        self.log_path = log_path
        self.start_time = time.time()
        self.file_handler: Optional[logging.FileHandler] = None
        self.access_count = 0
        self.eval_count = 0
        self.write_count = 0

    def initialize(self):
        """Initializes file logging handler for kintsugi_scanner_audit.log."""
        logger.handlers.clear()
        
        # Stream handler for console feedback
        console = logging.StreamHandler(sys.stdout)
        console_fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [SCANNER] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(console_fmt)
        logger.addHandler(console)

        # Audit file handler
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_handler = logging.FileHandler(self.log_path, mode="w", encoding="utf-8")
        file_fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        self.file_handler.setFormatter(file_fmt)
        logger.addHandler(self.file_handler)
        
        logger.setLevel(logging.DEBUG)
        self.log_event("INITIALIZE", f"Kintsugi-GRC Scanner Engine audit session started. Audit log target: {self.log_path.as_posix()}")

    def log_event(self, event_type: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Logs a formatted audit event."""
        detail_str = f" | Details: {details}" if details else ""
        log_msg = f"[{event_type}] {message}{detail_str}"
        logger.info(log_msg)

    def log_read_access(self, file_path: Path, bytes_read: int, mode_octal: str = "N/A"):
        """Logs a file read access event."""
        self.access_count += 1
        self.log_event(
            "ACCESS_READ",
            f"Read {bytes_read} bytes from file: {file_path.as_posix()}",
            {"bytes": bytes_read, "permissions": mode_octal}
        )

    def log_traverse(self, dir_path: Path, child_count: int):
        """Logs a directory traversal event."""
        self.log_event(
            "ACCESS_TRAVERSE",
            f"Traversed directory: {dir_path.as_posix()} ({child_count} children found)",
            {"dir": dir_path.as_posix(), "children": child_count}
        )

    def log_evaluation(self, file_path: Path, rule_id: str, status: str, details: Optional[Dict[str, Any]] = None):
        """Logs a rule evaluation event."""
        self.eval_count += 1
        self.log_event(
            "RULE_EVALUATION",
            f"Evaluated rule '{rule_id}' on {file_path.as_posix()} -> Status: {status}",
            details
        )

    def log_iam_lookup(self, identity: str, role: str, status: str):
        """Logs an Active Directory IAM access lookup."""
        self.log_event(
            "IAM_LOOKUP",
            f"Resolved identity '{identity}' ({role}) -> Least Privilege Status: {status}"
        )

    def log_write_event(self, target_file: Path, bytes_written: int, description: str):
        """Logs a file write event."""
        self.write_count += 1
        self.log_event(
            "WRITE_EVENT",
            f"Wrote {bytes_written} bytes to {target_file.as_posix()} ({description})",
            {"target": target_file.as_posix(), "bytes": bytes_written}
        )

    def finalize(self, total_files: int, total_findings: int) -> float:
        """Finalizes the audit session and logs summary statistics."""
        elapsed = time.time() - self.start_time
        self.log_event(
            "SUMMARY",
            f"Scan completed in {elapsed:.3f}s. Scanned {total_files} files ({self.access_count} read events, {self.eval_count} rule evaluations). Generated {total_findings} findings.",
            {"elapsed_seconds": round(elapsed, 3), "files_scanned": total_files, "total_findings": total_findings}
        )
        if self.file_handler:
            self.file_handler.flush()
            self.file_handler.close()
        return elapsed
