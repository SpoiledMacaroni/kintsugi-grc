"""
Kintsugi-GRC Scan Reporter & Terminal UI Formatter
Generates structured JSON scan findings reports (scan_report.json),
renders terminal compliance UI dashboards, and compares actual scanner output 
against expected_scan_results.json QA test assertions.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kintsugi_reporter")

class ScanReporter:
    """Formats scan findings into JSON reports and rich terminal UI output."""
    
    @staticmethod
    def save_json_report(scan_summary: Dict[str, Any], output_path: Path) -> Path:
        """Saves scan summary and findings into structured JSON report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report_bytes = json.dumps(scan_summary, indent=2).encode("utf-8")
        with open(output_path, "wb") as f:
            f.write(report_bytes)
        logger.info(f"Saved structured scan report ({len(report_bytes)} bytes) to {output_path.as_posix()}")
        return output_path

    @staticmethod
    def print_terminal_summary(scan_summary: Dict[str, Any]):
        """Prints a human-readable CLI summary table of scan findings."""
        score = scan_summary.get("compliance_score", 0)
        sev = scan_summary.get("severity_counts", {})
        findings = scan_summary.get("findings", [])

        # Color codes
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        score_color = GREEN if score >= 80 else (YELLOW if score >= 60 else RED)

        print("\n" + "="*80)
        print(f"{BOLD}{CYAN}   KINTSUGI-GRC SECURITY & COMPLIANCE SCAN SUMMARY{RESET}")
        print("="*80)
        print(f" Target Directory   : {scan_summary.get('target_directory')}")
        print(f" Total Files Scanned: {scan_summary.get('total_files_scanned')}")
        print(f" Compliance Score   : {score_color}{BOLD}{score}%{RESET}")
        print("-"*80)
        print(f" Severity Breakdown : {RED}CRITICAL: {sev.get('CRITICAL',0)}{RESET} | {RED}HIGH: {sev.get('HIGH',0)}{RESET} | {YELLOW}MEDIUM: {sev.get('MEDIUM',0)}{RESET} | {GREEN}PASS: {sev.get('PASS',0)}{RESET}")
        print("="*80)

        if not findings:
            print(f"{GREEN}✓ Zero compliance violations detected. All scanned files are compliant.{RESET}\n")
            return

        print(f"{BOLD}DETAILED FINDINGS BREAKDOWN:{RESET}")
        for idx, f in enumerate(findings, 1):
            severity = f.get("severity", "INFO")
            color = RED if severity in ["CRITICAL", "HIGH"] else (YELLOW if severity == "MEDIUM" else GREEN)
            print(f"\n  [{idx}] {color}{BOLD}{severity}{RESET} | {BOLD}{f.get('title')}{RESET}")
            print(f"      File     : {f.get('file_path')}")
            print(f"      Rule ID  : {f.get('rule_id')}")
            print(f"      Description: {f.get('description')}")
            
            mappings = f.get("framework_mappings", [])
            if mappings:
                citations_str = ", ".join(f"{m.get('framework')}:{m.get('control_id')}" for m in mappings[:4])
                print(f"      Controls : {CYAN}{citations_str}{RESET}")

        print("\n" + "="*80 + "\n")

    @staticmethod
    def compare_with_expected(target_dir: Path, scan_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Compares actual scanner findings against expected_scan_results.json QA test assertions."""
        expected_json = target_dir / "expected_scan_results.json"
        if not expected_json.exists():
            return {"status": "NO_EXPECTED_MANIFEST", "match_rate": 0.0}

        try:
            with open(expected_json, "r", encoding="utf-8") as f:
                expected_data = json.load(f)

            expected_findings = expected_data.get("expected_findings", [])
            expected_fails = [f for f in expected_findings if f.get("compliance_status") in ["FAIL", "WARNING"]]
            actual_fails = [f for f in scan_summary.get("findings", []) if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]]

            actual_fail_paths = {f["file_path"] for f in actual_fails}

            matched_count = 0
            missed_paths = []
            for exp in expected_fails:
                exp_path = exp["file_path"]
                is_matched = any(
                    act_path == exp_path or 
                    act_path.endswith("/" + exp_path) or 
                    exp_path.endswith("/" + act_path)
                    for act_path in actual_fail_paths
                )
                if is_matched:
                    matched_count += 1
                else:
                    missed_paths.append(exp_path)

            total_expected = len(expected_fails)
            match_rate = (matched_count / total_expected * 100.0) if total_expected > 0 else 100.0

            return {
                "status": "COMPARED",
                "total_expected_violations": total_expected,
                "detected_violations": matched_count,
                "match_rate": round(match_rate, 1),
                "missed_paths": missed_paths
            }
        except Exception as e:
            logger.warning(f"Failed to compare with expected_scan_results.json: {e}")
            return {"status": "ERROR", "match_rate": 0.0}
