"""
Kintsugi-GRC PDF Compliance Report Exporter
Generates structured executive PDF compliance reports (scan_report.pdf)
with severity breakdowns, findings lists, risk scores, and GRC framework citations.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("kintsugi_pdf_exporter")

class PDFComplianceExporter:
    """Exports scan findings into a structured PDF compliance report."""

    @staticmethod
    def _escape_pdf_str(text: str) -> str:
        """Escapes special PDF characters and newlines in raw strings."""
        if not text:
            return ""
        clean = str(text).replace("\r", " ").replace("\n", " ")
        return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    @classmethod
    def generate_pdf_report(cls, scan_summary: Dict[str, Any], output_path: Path) -> Path:
        """Generates a structured multi-page PDF 1.4 compliance audit report file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        target_dir = scan_summary.get("target_directory", "N/A")
        total_files = scan_summary.get("total_files_scanned", 0)
        score = scan_summary.get("compliance_score", 0)
        sev_counts = scan_summary.get("severity_counts", {})
        findings = scan_summary.get("findings", [])

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Collect top 3 priority non-PASS findings
        sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        non_pass_findings = [f for f in findings if f.get("severity") != "PASS"]
        top_3_issues = sorted(non_pass_findings, key=lambda x: (sev_rank.get(x.get("severity", "LOW"), 0), x.get("rule_id", "")), reverse=True)[:3]

        remediation_hints = {
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": "chmod 640 file",
            "ERR-OCTAL-WORLD-WRITABLE": "chmod 640 file",
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": "Encrypt payload via GPG / AES-256-CBC",
            "ERR-ENTROPY-PLAINTEXT-PII": "Encrypt payload via GPG / AES-256-CBC",
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": "Enforce SSH Protocol 2 in sshd_config",
            "INSECURE_SYSTEM_TLS_POLICY": "Set MinProtocol = TLSv1.2 in OpenSSL/Nginx",
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": "Set PASS_MAX_DAYS <= 90 in login.defs",
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": "Set non-human shell to /sbin/nologin",
            "INSECURE_AUDIT_LOG_PERMISSIONS": "chmod 600 /var/log/audit/audit.log",
            "UNENCRYPTED_RAW_ZLIB_STREAM": "Encrypt zlib stream via AES-256-CBC",
            "DECOMPRESSION_SAFETY_BOMB_TEST": "Verify zip decompression ratio < 100:1"
        }

        # ---------------------------------------------------------------------
        # BUILD PAGE 1 STREAM: EXECUTIVE SUMMARY, SEVERITY BAR & TOP 3 ISSUES
        # ---------------------------------------------------------------------
        p1_cmds = []
        # Header banner
        p1_cmds.append("0.08 0.18 0.36 rg")  # Dark blue
        p1_cmds.append("20 720 572 50 re f")
        p1_cmds.append("1 1 1 rg")  # White
        p1_cmds.append("BT /F2 18 Tf 35 740 Td (KINTSUGI-GRC AUDIT COMPLIANCE REPORT) Tj ET")
        p1_cmds.append("BT /F1 10 Tf 35 728 Td (Generated: " + cls._escape_pdf_str(timestamp) + ") Tj ET")

        # Executive Summary Section
        p1_cmds.append("0 0 0 rg")
        p1_cmds.append("BT /F2 12 Tf 35 690 Td (1. EXECUTIVE COMPLIANCE DASHBOARD) Tj ET")
        p1_cmds.append("0.8 0.8 0.8 RG 1 w 35 682 m 577 682 l S")

        p1_cmds.append("BT /F1 10 Tf 35 665 Td (Target Environment : " + cls._escape_pdf_str(target_dir[:60]) + ") Tj ET")
        p1_cmds.append("BT /F1 10 Tf 35 650 Td (Total Files Scanned : " + str(total_files) + ") Tj ET")
        p1_cmds.append("BT /F2 11 Tf 35 635 Td (Overall Health Score : " + str(score) + "% / 100%) Tj ET")

        # Severity breakdown & Visual Bar Box
        p1_cmds.append("0.95 0.95 0.97 rg 35 555 542 65 re f 0.7 0.7 0.7 RG 1 w 35 555 542 65 re S")
        p1_cmds.append("0 0 0 rg")
        p1_cmds.append("BT /F2 10 Tf 45 602 Td (SEVERITY BREAKDOWN & DISTRIBUTION:) Tj ET")
        
        crits = sev_counts.get("CRITICAL", 0)
        highs = sev_counts.get("HIGH", 0)
        meds = sev_counts.get("MEDIUM", 0)
        passes = sev_counts.get("PASS", 0)
        total_sev = crits + highs + meds + passes if (crits + highs + meds + passes) > 0 else 1

        p1_cmds.append("0.8 0.1 0.1 rg")
        p1_cmds.append(f"BT /F2 9 Tf 50 587 Td (CRITICAL: {crits}) Tj ET")
        p1_cmds.append("0.8 0.4 0.0 rg")
        p1_cmds.append(f"BT /F2 9 Tf 160 587 Td (HIGH: {highs}) Tj ET")
        p1_cmds.append("0.7 0.6 0.0 rg")
        p1_cmds.append(f"BT /F2 9 Tf 270 587 Td (MEDIUM: {meds}) Tj ET")
        p1_cmds.append("0.1 0.6 0.2 rg")
        p1_cmds.append(f"BT /F2 9 Tf 380 587 Td (PASS: {passes}) Tj ET")

        # Visual Severity Distribution Bar (Stacked bar chart)
        bar_x = 45
        bar_y = 565
        bar_total_w = 522
        
        c_w = int((crits / total_sev) * bar_total_w)
        h_w = int((highs / total_sev) * bar_total_w)
        m_w = int((meds / total_sev) * bar_total_w)
        p_w = bar_total_w - (c_w + h_w + m_w)

        if c_w > 0:
            p1_cmds.append("0.93 0.27 0.27 rg")
            p1_cmds.append(f"{bar_x} {bar_y} {c_w} 12 re f")
            bar_x += c_w
        if h_w > 0:
            p1_cmds.append("0.98 0.45 0.09 rg")
            p1_cmds.append(f"{bar_x} {bar_y} {h_w} 12 re f")
            bar_x += h_w
        if m_w > 0:
            p1_cmds.append("0.92 0.70 0.03 rg")
            p1_cmds.append(f"{bar_x} {bar_y} {m_w} 12 re f")
            bar_x += m_w
        if p_w > 0:
            p1_cmds.append("0.13 0.77 0.37 rg")
            p1_cmds.append(f"{bar_x} {bar_y} {p_w} 12 re f")

        # Top 3 Urgent Remediation Issues Section
        p1_cmds.append("0 0 0 rg")
        p1_cmds.append("BT /F2 12 Tf 35 530 Td (2. TOP 3 PRIORITY REMEDIATION ISSUES) Tj ET")
        p1_cmds.append("0.8 0.8 0.8 RG 1 w 35 522 m 577 522 l S")

        if not top_3_issues:
            p1_cmds.append("0.9 0.97 0.9 rg 35 440 542 65 re f 0.2 0.7 0.3 RG 1 w 35 440 542 65 re S")
            p1_cmds.append("0.1 0.6 0.2 rg")
            p1_cmds.append("BT /F2 11 Tf 50 480 Td (ZERO ACTIVE VIOLATIONS DETECTED!) Tj ET")
            p1_cmds.append("BT /F1 9 Tf 50 460 Td (All target files pass GRC security and encryption baseline checks.) Tj ET")
        else:
            y_box = 390
            for idx, item in enumerate(top_3_issues, 1):
                sev = item.get("severity", "MEDIUM")
                file_path = item.get("file_path", "N/A")[:55]
                rule_id = item.get("rule_id", "N/A")
                title = item.get("title", "Violation")[:60]
                
                advisory = item.get("rag_advisory", {})
                rem_cmd = advisory.get("remediation_command", remediation_hints.get(rule_id, "Align controls with GRC standard"))

                # Color box background
                if sev == "CRITICAL":
                    p1_cmds.append("0.99 0.93 0.93 rg 0.93 0.27 0.27 RG")
                elif sev == "HIGH":
                    p1_cmds.append("1.0 0.95 0.91 rg 0.98 0.45 0.09 RG")
                else:
                    p1_cmds.append("1.0 0.99 0.90 rg 0.92 0.70 0.03 RG")
                
                p1_cmds.append(f"35 {y_box} 542 115 re f 1 w 35 {y_box} 542 115 re S")

                # Content text
                p1_cmds.append("0 0 0 rg")
                p1_cmds.append(f"BT /F2 10 Tf 45 {y_box+95} Td ([#{idx} URGENT FIX] [{sev}] - {cls._escape_pdf_str(title)}) Tj ET")
                p1_cmds.append(f"BT /F1 9 Tf 45 {y_box+78} Td (Target File : {cls._escape_pdf_str(file_path)}) Tj ET")
                p1_cmds.append(f"BT /F1 9 Tf 45 {y_box+63} Td (Rule ID     : {cls._escape_pdf_str(rule_id)}) Tj ET")

                mappings = item.get("framework_mappings", [])
                citations = ", ".join(f"{m.get('framework')}:{m.get('control_id')}" for m in mappings[:3]) if mappings else "GRC Baseline Standard"
                p1_cmds.append("0.1 0.3 0.6 rg")
                p1_cmds.append(f"BT /F1 9 Tf 45 {y_box+48} Td (Citations   : {cls._escape_pdf_str(citations)}) Tj ET")

                p1_cmds.append("0.8 0.1 0.1 rg")
                p1_cmds.append(f"BT /F2 9 Tf 45 {y_box+25} Td (Actionable Fix: {cls._escape_pdf_str(rem_cmd[:65])}) Tj ET")

                y_box -= 125

        # Footer P1
        p1_cmds.append("0.5 0.5 0.5 rg")
        p1_cmds.append("BT /F1 8 Tf 35 25 Td (Kintsugi-GRC Executive Compliance Report - Page 1 - Executive Summary & Priority Action Plan) Tj ET")

        pages_streams = [ "\n".join(p1_cmds) ]

        # ---------------------------------------------------------------------
        # BUILD PAGE 2+ STREAMS: COMPREHENSIVE FINDINGS LEDGER (ALL FINDINGS)
        # ---------------------------------------------------------------------
        findings_per_page = 10
        total_findings_count = len(findings)

        if total_findings_count == 0:
            # Add single clean findings page if no findings
            p2_cmds = []
            p2_cmds.append("0.08 0.18 0.36 rg 20 720 572 50 re f 1 1 1 rg")
            p2_cmds.append("BT /F2 16 Tf 35 740 Td (DETAILED COMPLIANCE FINDINGS LEDGER) Tj ET")
            p2_cmds.append("BT /F1 10 Tf 35 728 Td (All Monitored Environment System Findings) Tj ET")
            p2_cmds.append("0 0 0 rg BT /F2 11 Tf 35 680 Td (Zero findings generated during this scan.) Tj ET")
            p2_cmds.append("0.5 0.5 0.5 rg BT /F1 8 Tf 35 25 Td (Kintsugi-GRC Audit Report - Detailed Ledger) Tj ET")
            pages_streams.append("\n".join(p2_cmds))
        else:
            for page_idx in range(0, total_findings_count, findings_per_page):
                page_num = (page_idx // findings_per_page) + 2
                chunk = findings[page_idx : page_idx + findings_per_page]

                p_cmds = []
                p_cmds.append("0.08 0.18 0.36 rg 20 720 572 50 re f 1 1 1 rg")
                p_cmds.append("BT /F2 16 Tf 35 740 Td (DETAILED COMPLIANCE FINDINGS LEDGER) Tj ET")
                p_cmds.append("BT /F1 10 Tf 35 728 Td (Showing findings " + str(page_idx + 1) + " to " + str(page_idx + len(chunk)) + " of " + str(total_findings_count) + ") Tj ET")

                p_cmds.append("0 0 0 rg")
                p_cmds.append("BT /F2 11 Tf 35 690 Td (ALL MONITORED SYSTEM FINDINGS & CONTROL MAPPINGS) Tj ET")
                p_cmds.append("0.8 0.8 0.8 RG 1 w 35 682 m 577 682 l S")

                y = 660
                for idx, f in enumerate(chunk, page_idx + 1):
                    severity = f.get("severity", "INFO")
                    title = f.get("title", "Finding")[:55]
                    file_path = f.get("file_path", "N/A")[:65]
                    rule_id = f.get("rule_id", "N/A")

                    if severity == "CRITICAL":
                        p_cmds.append("0.8 0.1 0.1 rg")
                    elif severity == "HIGH":
                        p_cmds.append("0.8 0.4 0.0 rg")
                    elif severity == "MEDIUM":
                        p_cmds.append("0.7 0.6 0.0 rg")
                    else:
                        p_cmds.append("0.1 0.6 0.2 rg")

                    p_cmds.append(f"BT /F2 9 Tf 35 {y} Td ([{idx}] [{severity}]) Tj ET")
                    p_cmds.append("0 0 0 rg")
                    p_cmds.append(f"BT /F2 9 Tf 110 {y} Td ({cls._escape_pdf_str(title)}) Tj ET")

                    y -= 14
                    p_cmds.append(f"BT /F1 8 Tf 45 {y} Td (File: {cls._escape_pdf_str(file_path)} | Rule: {cls._escape_pdf_str(rule_id)}) Tj ET")

                    mappings = f.get("framework_mappings", [])
                    if mappings:
                        y -= 12
                        citations = ", ".join(f"{m.get('framework')}:{m.get('control_id')}" for m in mappings[:3])
                        p_cmds.append("0.1 0.3 0.6 rg")
                        p_cmds.append(f"BT /F1 8 Tf 45 {y} Td (Controls: {cls._escape_pdf_str(citations)}) Tj ET")
                        p_cmds.append("0 0 0 rg")

                    y -= 18

                p_cmds.append("0.5 0.5 0.5 rg")
                p_cmds.append(f"BT /F1 8 Tf 35 25 Td (Kintsugi-GRC Executive Compliance Report - Page {page_num} - Complete Findings Ledger) Tj ET")
                pages_streams.append("\n".join(p_cmds))

        # ---------------------------------------------------------------------
        # DYNAMIC MULTI-PAGE PDF 1.4 STREAM & OBJECT ASSEMBLY
        # ---------------------------------------------------------------------
        header_bytes = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        n_pages = len(pages_streams)

        obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        kids = ["3 0 R"] + [f"{7 + 2*(i-1)} 0 R" for i in range(1, n_pages)]
        kids_str = " ".join(kids)
        obj2 = f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {n_pages} >>\nendobj\n"
        obj4 = "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        obj5 = "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n"

        obj_dict = {
            1: obj1.encode("latin-1"),
            2: obj2.encode("latin-1"),
            4: obj4.encode("latin-1"),
            5: obj5.encode("latin-1")
        }

        for k, stream_text in enumerate(pages_streams, 1):
            if k == 1:
                page_obj_id = 3
                stream_obj_id = 6
            else:
                page_obj_id = 7 + 2 * (k - 2)
                stream_obj_id = 8 + 2 * (k - 2)

            page_str = f"{page_obj_id} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents {stream_obj_id} 0 R >>\nendobj\n"
            obj_dict[page_obj_id] = page_str.encode("latin-1")

            s_bytes = stream_text.encode("latin-1", errors="replace")
            stream_str = f"{stream_obj_id} 0 obj\n<< /Length {len(s_bytes)} >>\nstream\n".encode("latin-1") + s_bytes + b"\nendstream\nendobj\n"
            obj_dict[stream_obj_id] = stream_str

        max_obj_id = max(obj_dict.keys())
        body_bytes = bytearray(header_bytes)
        offsets = [0] * (max_obj_id + 1)

        for obj_id in range(1, max_obj_id + 1):
            offsets[obj_id] = len(body_bytes)
            body_bytes.extend(obj_dict[obj_id])

        xref_offset = len(body_bytes)
        xref_lines = ["xref", f"0 {max_obj_id + 1}", "0000000000 65535 f "]
        for i in range(1, max_obj_id + 1):
            xref_lines.append(f"{offsets[i]:010d} 00000 n ")

        xref_lines.extend([
            "trailer",
            f"<< /Size {max_obj_id + 1} /Root 1 0 R >>",
            "startxref",
            str(xref_offset),
            "%%EOF\n"
        ])

        full_pdf = bytes(body_bytes) + "\n".join(xref_lines).encode("latin-1")

        with open(output_path, "wb") as f:
            f.write(full_pdf)

        logger.info(f"Successfully generated {n_pages}-page PDF report ({len(full_pdf)} bytes) at {output_path.as_posix()}")
        return output_path
