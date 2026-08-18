#!/usr/bin/env python3
"""
scripts/purge_synthetic.py

Purges synthetically generated data and test artifacts to restore the Kintsugi-GRC
environment to a clean, pristine baseline state before synthetic tests are generated
and compared.

Removes:
  - Synthetic industry environments (healthcare, merchant, finance, banking)
  - Generated encryption keys (.keys/) and expected result matrices
  - Scan and generation audit logs (synthetic_generation_audit.log, kintsugi_scanner_audit.log)
  - Generated scan reports (scan_report.json, scan_report.pdf)
  - Temporary test files and backups

Usage:
    python3 scripts/purge_synthetic.py
    python3 scripts/purge_synthetic.py --target-dir ./synthetic_test_env --all --force
    python3 scripts/purge_synthetic.py --dry-run
"""

import argparse
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Color constants for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


KNOWN_SYNTHETIC_DIRS = [
    "healthcare_production_env",
    "merchant_production_env",
    "finance_production_env",
    "banking_production_env",
    ".keys",
    "test_env",
]

KNOWN_SYNTHETIC_FILES = [
    "expected_scan_results.json",
    "synthetic_generation_audit.log",
    "kintsugi_scanner_audit.log",
    "synthetic_generation_audit.bak",
]

KNOWN_ROOT_ARTIFACTS = [
    "kintsugi_scanner_audit.log",
    "test_audit.log",
    "scan_report.json",
    "scan_report.pdf",
]


def purge_synthetic_data(
    target_dir: Path,
    purge_root_artifacts: bool = True,
    dry_run: bool = False,
    verbose: bool = False,
) -> Dict[str, any]:
    """
    Purges synthetic test environments, logs, and artifacts.
    
    Returns:
        Dict with summary counts: deleted_dirs, deleted_files, bytes_freed, etc.
    """
    target_dir = target_dir.resolve()
    stats = {
        "deleted_dirs": [],
        "deleted_files": [],
        "bytes_freed": 0,
        "errors": [],
    }

    print(f"\n{BOLD}{CYAN}═══ Kintsugi-GRC Synthetic Data Purge ═══{RESET}")
    print(f"{DIM}Target Directory:{RESET} {target_dir}")
    print(f"{DIM}Dry Run Mode:{RESET}    {'ENABLED (no files will be deleted)' if dry_run else 'DISABLED (live purge)'}\n")

    if not target_dir.exists():
        print(f"{YELLOW}Target directory does not exist: {target_dir} (nothing to purge){RESET}")
        return stats

    # 1. Purge known synthetic subdirectories
    for item in target_dir.iterdir():
        if item.is_dir() and (item.name in KNOWN_SYNTHETIC_DIRS or item.name.endswith("_env") or item.name == ".keys"):
            size = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
            file_count = sum(1 for _ in item.rglob("*") if _.is_file())
            stats["deleted_dirs"].append((item.name, file_count, size))
            stats["bytes_freed"] += size

            if dry_run:
                print(f"  {YELLOW}[DRY-RUN WOULD DELETE DIR]{RESET} {item.name}/ ({file_count} files, {size:,} bytes)")
            else:
                try:
                    # Clear read-only / restrictive permissions on files so shutil.rmtree succeeds
                    for p in item.rglob("*"):
                        try:
                            os.chmod(p, 0o777)
                        except Exception:
                            pass
                    shutil.rmtree(item)
                    print(f"  {RED}[PURGED DIRECTORY]{RESET} {item.name}/ ({file_count} files, {size:,} bytes)")
                except Exception as e:
                    stats["errors"].append((str(item), str(e)))
                    print(f"  {RED}[ERROR DELETING DIR]{RESET} {item.name}: {e}")

    # 2. Purge synthetic metadata / audit files in target_dir
    for item in target_dir.iterdir():
        if item.is_file() and (item.name in KNOWN_SYNTHETIC_FILES or item.name.endswith(".log") or item.name.endswith(".bak")):
            size = item.stat().st_size
            stats["deleted_files"].append((item.name, size))
            stats["bytes_freed"] += size

            if dry_run:
                print(f"  {YELLOW}[DRY-RUN WOULD DELETE FILE]{RESET} {item.name} ({size:,} bytes)")
            else:
                try:
                    try:
                        os.chmod(item, 0o666)
                    except Exception:
                        pass
                    item.unlink()
                    print(f"  {RED}[PURGED FILE]{RESET} {item.name} ({size:,} bytes)")
                except Exception as e:
                    stats["errors"].append((str(item), str(e)))
                    print(f"  {RED}[ERROR DELETING FILE]{RESET} {item.name}: {e}")

    # 3. Purge root-level scan reports and logs if requested
    if purge_root_artifacts:
        project_root = target_dir.parent if target_dir.name == "synthetic_test_env" else Path.cwd()
        for root_file_name in KNOWN_ROOT_ARTIFACTS:
            root_file = project_root / root_file_name
            if root_file.exists() and root_file.is_file():
                size = root_file.stat().st_size
                stats["deleted_files"].append((f"root:{root_file_name}", size))
                stats["bytes_freed"] += size

                if dry_run:
                    print(f"  {YELLOW}[DRY-RUN WOULD DELETE ROOT ARTIFACT]{RESET} {root_file_name} ({size:,} bytes)")
                else:
                    try:
                        try:
                            os.chmod(root_file, 0o666)
                        except Exception:
                            pass
                        root_file.unlink()
                        print(f"  {RED}[PURGED ROOT ARTIFACT]{RESET} {root_file_name} ({size:,} bytes)")
                    except Exception as e:
                        stats["errors"].append((str(root_file), str(e)))
                        print(f"  {RED}[ERROR DELETING ARTIFACT]{RESET} {root_file_name}: {e}")

    # Ensure target_dir still exists as an empty baseline directory
    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    # Print summary
    mb_freed = stats["bytes_freed"] / (1024 * 1024)
    print(f"\n{BOLD}{GREEN}✔ Purge Summary:{RESET}")
    print(f"  • Directories removed: {len(stats['deleted_dirs'])}")
    print(f"  • Files removed:       {len(stats['deleted_files'])}")
    print(f"  • Storage freed:       {mb_freed:.2f} MB ({stats['bytes_freed']:,} bytes)")
    if stats["errors"]:
        print(f"  • {RED}Encountered {len(stats['errors'])} errors during purge.{RESET}")
    else:
        print(f"  • {GREEN}Target environment is now in a clean default state ready for new synthetic tests.{RESET}\n")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Purge synthetically generated test environments, logs, and artifacts in Kintsugi-GRC."
    )
    parser.add_argument(
        "--target-dir", "-t",
        default="./synthetic_test_env",
        help="Path to synthetic test environment directory (default: ./synthetic_test_env)."
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        default=True,
        help="Purge both target environment data and root scan reports/audit logs (default: True)."
    )
    parser.add_argument(
        "--env-only",
        action="store_true",
        help="Only purge synthetic_test_env directory without deleting root scan reports or root audit logs."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the purge without deleting any files."
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Skip interactive confirmation prompt."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable detailed output."
    )

    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    purge_root = not args.env_only

    if not args.force and not args.dry_run:
        print(f"{YELLOW}Warning:{RESET} This will permanently delete all synthetic data in:")
        print(f"  → {target_dir}")
        if purge_root:
            print("  → Root audit logs and scan reports (scan_report.json, scan_report.pdf, *.log)")
        confirm = input(f"\nProceed with purge? [{BOLD}y/N{RESET}]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print(f"{CYAN}Purge cancelled by user.{RESET}")
            sys.exit(0)

    purge_synthetic_data(
        target_dir=target_dir,
        purge_root_artifacts=purge_root,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
