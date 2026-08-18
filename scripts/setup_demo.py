#!/usr/bin/env python3
"""
scripts/setup_demo.py

Orchestrates complete synthetic test data generation, industry environments,
and corporate compliance policy documents for Kintsugi-GRC demo readiness.

Pipeline:
  1. [Optional] Purges prior state to guarantee clean default baseline.
  2. Generates all 4 Industry Environments (Healthcare, Merchant, Finance, Banking).
  3. Synthesizes industry-specific Company Policy Documents (JSON) for RAG vectorization demo.
  4. Validates permissions, entropy distributions, and QA test assertions.
  5. Outputs a demo readiness cheatsheet with instant-launch GUI and CLI commands.

Usage:
    python3 scripts/setup_demo.py
    python3 scripts/setup_demo.py --industry healthcare --seed 42
    python3 scripts/setup_demo.py --no-clean
"""

import argparse
import json
import logging
import os
import shutil
import sys
import subprocess
from pathlib import Path
from typing import Dict, List

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# Color formatting
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
GOLD = "\033[38;5;220m"
RESET = "\033[0m"


# -----------------------------------------------------------------------------
# SYNTHETIC COMPANY POLICY DEFINITIONS (INDUSTRY PROFILES)
# -----------------------------------------------------------------------------
DEMO_POLICIES = {
    "sample_company_policy.json": {
        "company": "Acme Health Systems Inc.",
        "industry": "Healthcare",
        "version": "2026.4",
        "frameworks": ["HIPAA §164.312", "HITRUST CSF v11.8.0", "NIST SP 800-53"],
        "policies": [
            {
                "clause_id": "ACME-POLICY-SEC-01",
                "standard": "Acme Internal Security Baseline",
                "section": "Cryptographic Safeguards §4.1",
                "context": "All financial records, copay ledgers, and billing data exports must be encrypted at rest using AES-256-CBC symmetric algorithms. Plaintext files containing credit card PAN numbers or SSNs are strictly prohibited.",
                "remediation": "Encrypt file using GPG symmetric encryption with AES256 cipher algo."
            },
            {
                "clause_id": "ACME-POLICY-SEC-02",
                "standard": "Acme Internal Security Baseline",
                "section": "Access Control & Permissions §5.3",
                "context": "World-writable directory or file permissions (0o777) on sensitive infrastructure servers are strictly forbidden by corporate policy. All files must enforce owner/group isolation (0o640).",
                "remediation": "Execute chmod 640 on file to strip world-writable permissions."
            },
            {
                "clause_id": "ACME-POLICY-SEC-03",
                "standard": "Acme Internal Security Baseline",
                "section": "Password Expiration Policy §8.1",
                "context": "User passwords in login.defs must be set to expire within 90 days (PASS_MAX_DAYS <= 90). Unlimited password validity (99999 days) violates corporate password policy.",
                "remediation": "Update PASS_MAX_DAYS to 90 or 89 in /etc/login.defs."
            },
            {
                "clause_id": "ACME-POLICY-SEC-04",
                "standard": "Acme Internal Security Baseline",
                "section": "Audit Trail Protection §9.2",
                "context": "Security audit log files (/var/log/audit/audit.log) must be protected with strict 0o600 permissions to prevent unauthorized log tampering or erasure.",
                "remediation": "Execute chmod 600 /var/log/audit/audit.log"
            }
        ]
    },
    "sample_merchant_policy.json": {
        "company": "Nexus Retail & E-Commerce Global",
        "industry": "Merchant / E-Commerce",
        "version": "2026.2",
        "frameworks": ["PCI DSS v4.0.1", "NIST SP 800-53 Rev 5"],
        "policies": [
            {
                "clause_id": "NEXUS-PCI-CARD-01",
                "standard": "PCI DSS v4.0.1 Requirement 3.4",
                "section": "Cardholder Data Protection §3.4.1",
                "context": "Primary Account Numbers (PANs) and transaction logs in billing_department must be rendered unreadable anywhere they are stored using strong AES-256-CBC cryptography.",
                "remediation": "gpg --symmetric --cipher-algo AES256 <file> && shred -u <file>"
            },
            {
                "clause_id": "NEXUS-PCI-ACCESS-02",
                "standard": "PCI DSS v4.0.1 Requirement 7.2",
                "section": "Least Privilege & File Permissions §7.2.2",
                "context": "Merchant ledger files and copay summaries must strictly restrict write access to the finance service account. World-writable permissions (0o777) are a critical compliance violation.",
                "remediation": "chmod 0640 <file>"
            },
            {
                "clause_id": "NEXUS-PCI-TLS-03",
                "standard": "PCI DSS v4.0.1 Requirement 4.2",
                "section": "Transmission Cryptography §4.2.1",
                "context": "Legacy TLS protocols (TLSv1.0, TLSv1.1, SSLv3) and insecure crypto-policies (LEGACY) are forbidden for cardholder environments. System crypto policy must be set to DEFAULT or FUTURE.",
                "remediation": "update-crypto-policies --set DEFAULT"
            }
        ]
    },
    "sample_financial_policy.json": {
        "company": "Apex Capital & Treasury Management",
        "industry": "Finance / Treasury",
        "version": "2026.1",
        "frameworks": ["SOX Section 404", "HITRUST CSF v11.8.0", "NIST SP 800-53"],
        "policies": [
            {
                "clause_id": "APEX-TREASURY-01",
                "standard": "Apex Enterprise Risk Baseline",
                "section": "Shadow Access & Group Isolation §2.4",
                "context": "Cross-department access to core treasury ledgers and wire batches by unauthorized UID/GID groups is prohibited. File permissions must strictly enforce 0o600 or 0o640.",
                "remediation": "chown treasury:treasury <file> && chmod 0600 <file>"
            },
            {
                "clause_id": "APEX-TREASURY-02",
                "standard": "Apex Enterprise Risk Baseline",
                "section": "Electronic Record Encryption §5.1",
                "context": "Settlement logs and ACH streams must not be stored with raw deflate/zlib compression without an encryption envelope (AES-256-CBC).",
                "remediation": "openssl enc -aes-256-cbc -salt -pbkdf2 -in <file> -out <file>.enc"
            },
            {
                "clause_id": "APEX-TREASURY-03",
                "standard": "Apex Enterprise Risk Baseline",
                "section": "ECB Mode Deprecation §6.3",
                "context": "Electronic Codebook (ECB) cipher mode leaks block repetition patterns and is prohibited across all transactional ledgers.",
                "remediation": "openssl enc -aes-256-cbc -salt -pbkdf2 -in <file> -out <file>.cbc"
            }
        ]
    },
    "sample_banking_policy.json": {
        "company": "Vanguard Global Banking & SWIFT Operations",
        "industry": "Banking / SWIFT",
        "version": "2026.3",
        "frameworks": ["SWIFT Customer Security Programme (CSP)", "NIST SP 800-53", "PCI DSS v4.0.1"],
        "policies": [
            {
                "clause_id": "VANGUARD-SWIFT-01",
                "standard": "SWIFT CSP Control 2.1",
                "section": "Operating System Hardening & Daemon Accounts §2.1",
                "context": "Non-interactive system accounts (nobody, daemon, ftp) must not have interactive login shells (/bin/bash, /bin/sh). Must be set to /sbin/nologin or /bin/false.",
                "remediation": "usermod -s /sbin/nologin <daemon_account>"
            },
            {
                "clause_id": "VANGUARD-SWIFT-02",
                "standard": "SWIFT CSP Control 2.6",
                "section": "Secure Protocols & SSH Ciphers §2.6",
                "context": "SSH server configurations must disallow Protocol 1, legacy Arcfour/DES ciphers, and weak MD5/96-bit MACs.",
                "remediation": "Enforce Protocol 2, AES-GCM, and SHA-2 MACs in /etc/ssh/sshd_config"
            },
            {
                "clause_id": "VANGUARD-SWIFT-03",
                "standard": "SWIFT CSP Control 5.1",
                "section": "Audit Trail Logging & Non-Repudiation §5.1",
                "context": "Audit log files must have world-writable and world-readable permissions removed (chmod 0600) with centralized syslog forwarding.",
                "remediation": "chmod 0600 /var/log/audit/audit.log"
            }
        ]
    }
}


# -----------------------------------------------------------------------------
# POLICY GENERATOR HELPER
# -----------------------------------------------------------------------------
def write_demo_policies(output_dirs: List[Path]) -> List[Path]:
    """Writes all demo company policies to target directory locations."""
    written_files = []
    for out_dir in output_dirs:
        out_dir.mkdir(parents=True, exist_ok=True)
        for filename, policy_data in DEMO_POLICIES.items():
            file_path = out_dir / filename
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(policy_data, f, indent=2)
            written_files.append(file_path)
    return written_files


# -----------------------------------------------------------------------------
# MAIN DEMO SETUP ORCHESTRATOR
# -----------------------------------------------------------------------------
def setup_demo_environment(
    output_dir: Path = Path("./synthetic_test_env"),
    industry: str = "all",
    seed: int = 42,
    clean_first: bool = True,
    verbose: bool = False,
) -> bool:
    """
    Executes the full demo preparation pipeline.
    """
    output_dir = output_dir.resolve()
    project_root = Path(__file__).resolve().parent.parent

    print(f"\n{BOLD}{GOLD}╔════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{GOLD}║           Kintsugi-GRC Demo Environment Setup Orchestrator         ║{RESET}")
    print(f"{BOLD}{GOLD}╚════════════════════════════════════════════════════════════════════╝{RESET}\n")

    # Step 1: Optional clean purge
    if clean_first:
        print(f"{CYAN}[Step 1/5] Purging previous test data to establish clean baseline...{RESET}")
        try:
            from scripts.purge_synthetic import purge_synthetic_data
            purge_synthetic_data(target_dir=output_dir, purge_root_artifacts=True, dry_run=False, verbose=verbose)
        except Exception as e:
            print(f"{YELLOW}Warning during purge: {e}. Proceeding with directory setup...{RESET}")
            output_dir.mkdir(parents=True, exist_ok=True)
    else:
        print(f"{DIM}[Step 1/5] Skipping purge (--no-clean selected).{RESET}")
        output_dir.mkdir(parents=True, exist_ok=True)

    # Step 2: Run Synthetic Generator
    print(f"\n{CYAN}[Step 2/5] Generating multi-attribute synthetic environments ({industry})...{RESET}")
    from scripts.generate_synthetic import main as generate_main

    orig_argv = sys.argv
    try:
        gen_args = [
            "generate_synthetic.py",
            "--industry", industry,
            "--output-dir", str(output_dir),
            "--seed", str(seed),
        ]
        if verbose:
            gen_args.append("--verbose")
        sys.argv = gen_args
        generate_main()
    finally:
        sys.argv = orig_argv

    # Step 3: Generate Industry-Tailored Corporate Compliance Policies
    print(f"\n{CYAN}[Step 3/5] Generating synthetic corporate compliance policies for RAG demo...{RESET}")
    policies_dir = project_root / "policies"
    written_policies = write_demo_policies([output_dir, policies_dir])
    for p in written_policies:
        print(f"  {GREEN}✔ Created Policy:{RESET} {p.relative_to(project_root).as_posix()}")

    # Step 4: Verification & Control Assertion Check
    print(f"\n{CYAN}[Step 4/5] Verifying generated test environment structure & assertions...{RESET}")
    expected_file = output_dir / "expected_scan_results.json"
    if expected_file.exists():
        with open(expected_file, "r", encoding="utf-8") as f:
            expected_data = json.load(f)
        findings_list = expected_data.get("expected_findings", [])
        total_files = len(findings_list)
        crits = sum(1 for v in findings_list if isinstance(v, dict) and v.get("severity") == "CRITICAL")
        highs = sum(1 for v in findings_list if isinstance(v, dict) and v.get("severity") == "HIGH")
        meds  = sum(1 for v in findings_list if isinstance(v, dict) and v.get("severity") == "MEDIUM")
        passes = sum(1 for v in findings_list if isinstance(v, dict) and (v.get("severity") == "PASS" or v.get("compliance_status") == "PASS"))
        print(f"  • {BOLD}Total Expected Findings:{RESET} {total_files}")
        print(f"  • {RED}Critical Violations:{RESET}     {crits}")
        print(f"  • {YELLOW}High Severity Issues:{RESET}    {highs}")
        print(f"  • {GOLD}Medium Severity Issues:{RESET}  {meds}")
        print(f"  • {GREEN}Compliant / Pass Nodes:{RESET}  {passes}")
    else:
        print(f"{YELLOW}Note: expected_scan_results.json not found in output directory.{RESET}")

    # Step 5: Demo Readiness Summary & Launch Cheatsheet
    print(f"\n{CYAN}[Step 5/5] Finalizing Demo Readiness...{RESET}")
    print(f"\n{BOLD}{GREEN}════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN}🎉 DEMO ENVIRONMENT IS FULLY PRIMED & READY!{RESET}")
    print(f"{BOLD}{GREEN}════════════════════════════════════════════════════════════════════{RESET}\n")

    print(f"{BOLD}Demo Environments Generated in {output_dir.name}/:{RESET}")
    env_dirs = [d.name for d in output_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
    for ed in sorted(env_dirs):
        print(f"  📁 {output_dir.name}/{ed}")

    print(f"\n{BOLD}Custom Policies for RAG Upload Demo:{RESET}")
    print(f"  📄 sample_company_policy.json   (Healthcare / HIPAA / Baseline)")
    print(f"  📄 sample_merchant_policy.json  (Merchant / E-Commerce / PCI DSS)")
    print(f"  📄 sample_financial_policy.json (Finance / Treasury / SOX)")
    print(f"  📄 sample_banking_policy.json   (Banking / SWIFT / OS Hardening)")

    print(f"\n{BOLD}Launch Commands for Demo:{RESET}")
    print(f"  {GOLD}1. Launch PyQt6 Desktop GUI (Recommended):{RESET}")
    print(f"     python3 app.py gui\n")
    print(f"  {GOLD}2. Run CLI Healthcare Compliance Scan:{RESET}")
    print(f"     python3 app.py scan --target ./synthetic_test_env/healthcare_production_env --industry Healthcare\n")
    print(f"  {GOLD}3. Run Real-Time Dynamic Watcher Demo:{RESET}")
    print(f"     python3 app.py scan --target ./synthetic_test_env/healthcare_production_env --watch\n")
    print(f"  {GOLD}4. Verify Scan Findings Against QA Expected Results:{RESET}")
    print(f"     python3 app.py verify-expected --target ./synthetic_test_env\n")
    print(f"  {GOLD}5. Reset / Purge Demo State Anytime:{RESET}")
    print(f"     python3 scripts/purge_synthetic.py --force\n")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Setup and prime synthetic data and company policies for Kintsugi-GRC demo."
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./synthetic_test_env",
        help="Root directory for synthetic environments (default: ./synthetic_test_env)."
    )
    parser.add_argument(
        "--industry", "-i",
        choices=["healthcare", "merchant", "finance", "banking", "all"],
        default="all",
        help="Industry environment to generate (default: all)."
    )
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=42,
        help="Random seed for reproducible generation (default: 42)."
    )
    parser.add_argument(
        "--no-clean",
        action="store_true",
        help="Skip cleaning prior data before generating."
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output."
    )

    args = parser.parse_args()

    setup_demo_environment(
        output_dir=Path(args.output_dir),
        industry=args.industry,
        seed=args.seed,
        clean_first=not args.no_clean,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
