#!/usr/bin/env python3
"""
Kintsugi-GRC User Orchestration Application & Multi-Mode Runner
Provides Desktop GUI mode (app.py gui), CLI scanning mode (app.py scan), 
and PDF compliance report generation (app.py export-pdf).
"""

import argparse
import os
import sys
import time
from pathlib import Path

# Suppress benign Qt font database script lookup notices
os.environ.setdefault("QT_LOGGING_RULES", "qt.text.font.db=false;qt.text.font.*=false")

from src.dep_check import ensure_dependencies
ensure_dependencies()

from src.mapping.controls import ControlRegistry
from src.output.pdf_exporter import PDFComplianceExporter
from src.output.reporter import ScanReporter
from src.storage.framework_storage import FrameworkStorageClient
from src.rag.pipeline import RAGPipelineClient
from src.scanner.audit import ScannerAuditLogger
from src.scanner.engine import ScannerEngine
from src.ui.interface import launch_pyqt_gui


def main():
    parser = argparse.ArgumentParser(
        description="Kintsugi-GRC User Orchestration Application & Compliance Scanner Engine."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available Kintsugi-GRC CLI & GUI Commands")

    # Subcommand: gui
    gui_parser = subparsers.add_parser("gui", help="Launch Desktop GUI Application with target browser, live progress bar, violations filter, and PDF export.")

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Run automated GRC security & compliance scan over target environment.")
    scan_parser.add_argument(
        "--target", "-t",
        default="./synthetic_test_env",
        help="Target environment directory to scan (default: ./synthetic_test_env)."
    )
    scan_parser.add_argument(
        "--output", "-o",
        default="scan_report.json",
        help="Output filepath for structured JSON scan report (default: scan_report.json)."
    )
    scan_parser.add_argument(
        "--pdf", "-p",
        default="scan_report.pdf",
        help="Output filepath for compliance PDF report (default: scan_report.pdf)."
    )
    scan_parser.add_argument(
        "--controls", "-c",
        default="grc_controls.zip",
        help="Path to GRC control schema zip file (default: grc_controls.zip)."
    )
    scan_parser.add_argument(
        "--industry", "-i",
        default="All Industries",
        choices=["All Industries", "Healthcare", "Merchant / E-Commerce", "Finance / Treasury", "Banking / SWIFT"],
        help="Industry focus to filter framework control citations (default: All Industries)."
    )
    scan_parser.add_argument(
        "--audit-log", "-a",
        default="kintsugi_scanner_audit.log",
        help="Target file path for operation audit log (default: kintsugi_scanner_audit.log)."
    )
    scan_parser.add_argument(
        "--watch", "-w",
        action="store_true",
        help="Enable Dynamic Directory Watcher mode to actively re-scan file edits in real time."
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose DEBUG logging."
    )

    # Subcommand: export-pdf
    pdf_parser = subparsers.add_parser("export-pdf", help="Generate a PDF compliance audit report from an existing scan report JSON.")
    pdf_parser.add_argument(
        "--report", "-r",
        default="scan_report.json",
        help="Path to input scan report JSON file (default: scan_report.json)."
    )
    pdf_parser.add_argument(
        "--output", "-o",
        default="scan_report.pdf",
        help="Output filepath for generated PDF report (default: scan_report.pdf)."
    )

    # Subcommand: verify-expected
    verify_parser = subparsers.add_parser("verify-expected", help="Compare actual scan findings against expected_scan_results.json QA test assertions.")
    verify_parser.add_argument(
        "--target", "-t",
        default="./synthetic_test_env",
        help="Target environment directory containing expected_scan_results.json (default: ./synthetic_test_env)."
    )

    # Subcommand: summary
    summary_parser = subparsers.add_parser("summary", help="Display terminal dashboard summary for an existing scan report JSON.")
    summary_parser.add_argument(
        "--report", "-r",
        default="scan_report.json",
        help="Path to scan report JSON file (default: scan_report.json)."
    )

    # Subcommand: synthesize
    syn_parser = subparsers.add_parser("synthesize", help="Generate or regenerate synthetic test environments and internal corporate compliance policies.")
    syn_parser.add_argument(
        "--industry", "-i",
        choices=["healthcare", "merchant", "finance", "banking", "all"],
        default="all",
        help="Target industry environment to generate (default: all)."
    )
    syn_parser.add_argument(
        "--output-dir", "-o",
        default="./synthetic_test_env",
        help="Target root directory where synthetic environments will be created (default: ./synthetic_test_env)."
    )
    syn_parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Optional seed value for reproducible synthetic generation."
    )
    syn_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose DEBUG logging."
    )

    # Subcommand: purge
    purge_parser = subparsers.add_parser("purge", help="Purge synthetically generated test environments, logs, and reports.")
    purge_parser.add_argument(
        "--target-dir", "-t",
        default="./synthetic_test_env",
        help="Path to synthetic test environment directory (default: ./synthetic_test_env)."
    )
    purge_parser.add_argument(
        "--env-only",
        action="store_true",
        help="Only purge synthetic_test_env directory without deleting root scan reports or root audit logs."
    )
    purge_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Skip confirmation prompt."
    )
    purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the purge without deleting any files."
    )

    # Subcommand: setup-demo
    setup_parser = subparsers.add_parser("setup-demo", help="Generate all synthetic environments and company policies primed for demo.")
    setup_parser.add_argument(
        "--output-dir", "-o",
        default="./synthetic_test_env",
        help="Target root directory for synthetic environments (default: ./synthetic_test_env)."
    )
    setup_parser.add_argument(
        "--industry", "-i",
        choices=["healthcare", "merchant", "finance", "banking", "all"],
        default="all",
        help="Target industry environment to generate (default: all)."
    )
    setup_parser.add_argument(
        "--seed", "-s",
        type=int,
        default=42,
        help="Random seed for reproducible generation (default: 42)."
    )
    setup_parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Skip cleaning prior data before generating."
    )
    setup_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose DEBUG logging."
    )

    args = parser.parse_args()

    # Default action if no subcommand passed: launch GUI mode if display available, else run scan CLI
    if not args.command:
        if "DISPLAY" in sys.modules or sys.platform == "darwin":
            args.command = "gui"
        else:
            args.command = "scan"
            args.target = "./synthetic_test_env"
            args.output = "scan_report.json"
            args.pdf = "scan_report.pdf"
            args.controls = "grc_controls.zip"
            args.audit_log = "kintsugi_scanner_audit.log"
            args.verbose = False

    if args.command == "gui":
        print("Launching Kintsugi-GRC Desktop GUI Application (PyQt6)...")
        launch_pyqt_gui()

    elif args.command == "scan":
        target_dir = Path(args.target).resolve()
        output_file = Path(args.output).resolve()
        pdf_file = Path(args.pdf).resolve()
        controls_zip = Path(args.controls).resolve()
        audit_log_file = Path(args.audit_log).resolve()

        if not target_dir.exists():
            print(f"Error: Target directory '{target_dir.as_posix()}' does not exist.")
            sys.exit(1)

        # 1. Initialize Operation Audit Logger
        audit_logger = ScannerAuditLogger(audit_log_file)
        audit_logger.initialize()
        audit_logger.log_event("STARTUP", f"Target: {target_dir.as_posix()} | Output: {output_file.as_posix()}")

        # 2. Load Framework Control Mappings
        control_reg = ControlRegistry(controls_zip)
        control_reg.load()

        # 3. Connect to external component placeholders
        rag_client = RAGPipelineClient()
        rag_client.connect()

        storage_client = FrameworkStorageClient()
        storage_client.get_framework_references("HITRUST_v11.8.0")

        # 4. Instantiate & Run Scanner Engine
        industry_choice = getattr(args, "industry", "All Industries")
        engine = ScannerEngine(target_dir, control_reg, audit_logger, industry=industry_choice)
        scan_summary = engine.run_scan()

        # Attach RAG AI remediation advisory cards to findings
        for finding in scan_summary.get("findings", []):
            if finding.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                advisory = rag_client.generate_advisory(finding)
                finding["rag_advisory"] = advisory
                finding["rag_ai_remediation"] = advisory.get("remediation_command", "")

        # 5. Save JSON report, PDF compliance report, & audit log
        output_path = ScanReporter.save_json_report(scan_summary, output_file)
        audit_logger.log_write_event(output_path, output_path.stat().st_size, "Structured JSON Scan Findings Report")

        pdf_path = PDFComplianceExporter.generate_pdf_report(scan_summary, pdf_file)
        audit_logger.log_write_event(pdf_path, pdf_path.stat().st_size, "PDF Compliance Audit Report")

        # Save scan history via persistent SQLite database
        storage_client.save_scan_history(scan_summary)

        # 6. Check against expected QA assertions if present
        qa_result = ScanReporter.compare_with_expected(target_dir, scan_summary)
        if qa_result.get("status") == "COMPARED":
            audit_logger.log_event(
                "QA_ASSERTION",
                f"QA Assertion Match Rate: {qa_result['match_rate']}% ({qa_result['detected_violations']}/{qa_result['total_expected_violations']} expected violations detected)",
                qa_result
            )

        elapsed = audit_logger.finalize(scan_summary["total_files_scanned"], scan_summary["total_findings"])

        # 7. Print Terminal Compliance Dashboard
        ScanReporter.print_terminal_summary(scan_summary)

        if qa_result.get("status") == "COMPARED":
            print(f" QA Test Assertion Match Rate: \033[92m\033[1m{qa_result['match_rate']}%\033[0m ({qa_result['detected_violations']}/{qa_result['total_expected_violations']} violations matched)")
            print(f" Compliance PDF Report Exported: \033[96m{pdf_path.as_posix()}\033[0m")
            print(f" Operation Audit Log Written   : \033[96m{audit_log_file.as_posix()}\033[0m\n")

        if getattr(args, "watch", False):
            from src.scanner.watcher import DynamicDirectoryWatcher
            print(f" \033[93m\033[1m⚡ Dynamic Directory Watcher ACTIVE on '{target_dir.as_posix()}'. Monitoring file edits in real-time... (Press Ctrl+C to stop)\033[0m\n")

            def on_dynamic_change(path: Path, event: str):
                summary = engine.update_single_file(path, event)
                score = summary.get("compliance_score", 0)
                print(f" [\033[96mDYNAMIC WATCHER\033[0m] {event}: {path.name} | Updated Health Score: \033[92m{score}%\033[0m ({len(summary['findings'])} active findings)")

            watcher = DynamicDirectoryWatcher(target_dir, on_file_changed=on_dynamic_change, on_file_deleted=on_dynamic_change)
            watcher.start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                watcher.stop()
                print("\nDynamic Watcher stopped.")

    elif args.command == "export-pdf":
        report_file = Path(args.report).resolve()
        pdf_file = Path(args.output).resolve()
        if not report_file.exists():
            print(f"Report file {report_file.as_posix()} not found. Run 'python3 app.py scan' first.")
            sys.exit(1)
        import json
        with open(report_file, "r", encoding="utf-8") as f:
            summary = json.load(f)
        out_pdf = PDFComplianceExporter.generate_pdf_report(summary, pdf_file)
        print(f"Successfully generated PDF compliance report: {out_pdf.as_posix()}")

    elif args.command == "verify-expected":
        target_dir = Path(args.target).resolve()
        report_file = Path("scan_report.json").resolve()
        if not report_file.exists():
            print(f"Report file {report_file.as_posix()} not found. Run 'python3 app.py scan' first.")
            sys.exit(1)
        import json
        with open(report_file, "r", encoding="utf-8") as f:
            summary = json.load(f)
        qa = ScanReporter.compare_with_expected(target_dir, summary)
        print(f"QA Assertion Results: {json.dumps(qa, indent=2)}")

    elif args.command == "summary":
        report_file = Path(args.report).resolve()
        if not report_file.exists():
            print(f"Report file {report_file.as_posix()} not found.")
            sys.exit(1)
        import json
        with open(report_file, "r", encoding="utf-8") as f:
            summary = json.load(f)
        ScanReporter.print_terminal_summary(summary)

    elif args.command == "synthesize":
        from scripts.generate_synthetic import main as generate_main
        sys.argv = [
            "generate_synthetic.py",
            "--industry", args.industry,
            "--output-dir", args.output_dir,
        ]
        if args.seed is not None:
            sys.argv.extend(["--seed", str(args.seed)])
        if args.verbose:
            sys.argv.append("--verbose")
        generate_main()

    elif args.command == "purge":
        from scripts.purge_synthetic import purge_synthetic_data
        target_dir = Path(args.target_dir).resolve()
        if not args.force and not args.dry_run:
            print(f"\033[93mWarning:\033[0m This will permanently delete all synthetic data in: {target_dir}")
            confirm = input("Proceed with purge? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Purge cancelled.")
                sys.exit(0)
        purge_synthetic_data(
            target_dir=target_dir,
            purge_root_artifacts=not args.env_only,
            dry_run=args.dry_run,
        )

    elif args.command == "setup-demo":
        from scripts.setup_demo import setup_demo_environment
        setup_demo_environment(
            output_dir=Path(args.output_dir),
            industry=args.industry,
            seed=args.seed,
            clean_first=not args.no_clean,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    main()
