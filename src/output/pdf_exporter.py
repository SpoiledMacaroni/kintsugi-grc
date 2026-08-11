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
        """Escapes special PDF characters in raw strings."""
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    @classmethod
    def generate_pdf_report(cls, scan_summary: Dict[str, Any], output_path: Path) -> Path:
        """Generates a valid PDF 1.4 compliance audit report file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        target_dir = scan_summary.get("target_directory", "N/A")
        total_files = scan_summary.get("total_files_scanned", 0)
        score = scan_summary.get("compliance_score", 0)
        sev_counts = scan_summary.get("severity_counts", {})
        findings = scan_summary.get("findings", [])

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Construct raw PDF 1.4 stream content
        lines = []
        lines.append("%PDF-1.4")
        lines.append("%\xe2\xe3\xcf\xd3")

        # Object 1: Catalog
        lines.append("1 0 obj")
        lines.append("<< /Type /Catalog /Pages 2 0 R >>")
        lines.append("endobj")

        # Object 2: Pages
        lines.append("2 0 obj")
        lines.append("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        lines.append("endobj")

        # Object 3: Page 1
        lines.append("3 0 obj")
        lines.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>")
        lines.append("endobj")

        # Object 4: Font Helvetica
        lines.append("4 0 obj")
        lines.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        lines.append("endobj")

        # Object 5: Font Helvetica-Bold
        lines.append("5 0 obj")
        lines.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        lines.append("endobj")

        # Build Page Contents Stream
        stream_cmds = []
        # Header banner (dark blue box)
        stream_cmds.append("0.08 0.18 0.36 rg")  # Dark blue
        stream_cmds.append("20 720 572 50 re f")
        
        # Header title (white text)
        stream_cmds.append("1 1 1 rg")  # White
        stream_cmds.append("BT /F2 18 Tf 35 740 Td (KINTSUGI-GRC AUDIT COMPLIANCE REPORT) Tj ET")
        stream_cmds.append("BT /F1 10 Tf 35 728 Td (Generated: " + cls._escape_pdf_str(timestamp) + ") Tj ET")

        # Executive Summary Section
        stream_cmds.append("0 0 0 rg")  # Black
        stream_cmds.append("BT /F2 12 Tf 35 690 Td (EXECUTIVE COMPLIANCE SUMMARY) Tj ET")
        stream_cmds.append("0.8 0.8 0.8 RG 1 w 35 682 m 577 682 l S")  # Horizontal line

        stream_cmds.append("BT /F1 10 Tf 35 665 Td (Target Environment : " + cls._escape_pdf_str(target_dir[:60]) + ") Tj ET")
        stream_cmds.append("BT /F1 10 Tf 35 650 Td (Total Files Scanned : " + str(total_files) + ") Tj ET")
        stream_cmds.append("BT /F2 11 Tf 35 635 Td (Overall Risk Score   : " + str(score) + "% / 100%) Tj ET")

        # Severity breakdown metrics box
        stream_cmds.append("0.95 0.95 0.97 rg 35 575 542 45 re f 0.7 0.7 0.7 RG 1 w 35 575 542 45 re S")
        stream_cmds.append("0.8 0.1 0.1 rg")  # Red
        stream_cmds.append(f"BT /F2 10 Tf 50 595 Td (CRITICAL: {sev_counts.get('CRITICAL',0)}) Tj ET")
        stream_cmds.append("0.8 0.4 0.0 rg")  # Orange
        stream_cmds.append(f"BT /F2 10 Tf 160 595 Td (HIGH: {sev_counts.get('HIGH',0)}) Tj ET")
        stream_cmds.append("0.7 0.6 0.0 rg")  # Yellow
        stream_cmds.append(f"BT /F2 10 Tf 270 595 Td (MEDIUM: {sev_counts.get('MEDIUM',0)}) Tj ET")
        stream_cmds.append("0.1 0.6 0.2 rg")  # Green
        stream_cmds.append(f"BT /F2 10 Tf 380 595 Td (PASS: {sev_counts.get('PASS',0)}) Tj ET")

        # Findings Detail Table Header
        stream_cmds.append("0 0 0 rg")
        stream_cmds.append("BT /F2 12 Tf 35 550 Td (TOP DETECTED FINDINGS & FRAMEWORK CONTROL MAPPINGS) Tj ET")
        stream_cmds.append("0.8 0.8 0.8 RG 1 w 35 542 m 577 542 l S")

        # Render top findings
        y = 520
        top_findings = findings[:12]  # First page findings display
        for idx, f in enumerate(top_findings, 1):
            if y < 60:
                break
            severity = f.get("severity", "INFO")
            title = f.get("title", "Finding")[:55]
            file_path = f.get("file_path", "N/A")[:65]
            rule_id = f.get("rule_id", "N/A")

            # Color coding for severity
            if severity == "CRITICAL":
                stream_cmds.append("0.8 0.1 0.1 rg")
            elif severity == "HIGH":
                stream_cmds.append("0.8 0.4 0.0 rg")
            elif severity == "MEDIUM":
                stream_cmds.append("0.7 0.6 0.0 rg")
            else:
                stream_cmds.append("0.1 0.6 0.2 rg")

            stream_cmds.append(f"BT /F2 9 Tf 35 {y} Td ([{idx}] [{severity}]) Tj ET")
            stream_cmds.append("0 0 0 rg")
            stream_cmds.append(f"BT /F2 9 Tf 110 {y} Td ({cls._escape_pdf_str(title)}) Tj ET")
            
            y -= 14
            stream_cmds.append(f"BT /F1 8 Tf 45 {y} Td (File: {cls._escape_pdf_str(file_path)} | Rule: {cls._escape_pdf_str(rule_id)}) Tj ET")

            mappings = f.get("framework_mappings", [])
            if mappings:
                y -= 12
                citations = ", ".join(f"{m.get('framework')}:{m.get('control_id')}" for m in mappings[:3])
                stream_cmds.append("0.1 0.3 0.6 rg")
                stream_cmds.append(f"BT /F1 8 Tf 45 {y} Td (Controls: {cls._escape_pdf_str(citations)}) Tj ET")
                stream_cmds.append("0 0 0 rg")

            y -= 16

        # Footer
        stream_cmds.append("0.5 0.5 0.5 rg")
        stream_cmds.append("BT /F1 8 Tf 35 25 Td (Kintsugi-GRC Automated Compliance Scanner - Confidential Audit Document) Tj ET")

        stream_body = "\n".join(stream_cmds)
        stream_bytes = stream_body.encode("latin-1", errors="replace")

        # Object 6: Stream
        lines.append("6 0 obj")
        lines.append(f"<< /Length {len(stream_bytes)} >>")
        lines.append("stream")

        # Combine text lines and binary stream
        header_text = "\n".join(lines) + "\n"
        footer_text = f"\nendstream\nendobj\n"

        # Calculate object offsets for xref
        header_bytes = header_text.encode("latin-1")
        footer_bytes = footer_text.encode("latin-1")

        obj6_offset = len(header_bytes)
        end_obj6 = header_bytes + stream_bytes + footer_bytes

        xref_start = len(end_obj6)
        xref_lines = []
        xref_lines.append("xref")
        xref_lines.append("0 7")
        xref_lines.append("0000000000 65535 f ")
        xref_lines.append("0000000015 00000 n ")
        xref_lines.append("0000000068 00000 n ")
        xref_lines.append("0000000125 00000 n ")
        xref_lines.append("0000000257 00000 n ")
        xref_lines.append("0000000331 00000 n ")
        xref_lines.append(f"{obj6_offset:010d} 00000 n ")
        xref_lines.append("trailer")
        xref_lines.append("<< /Size 7 /Root 1 0 R >>")
        xref_lines.append("startxref")
        xref_lines.append(str(xref_start))
        xref_lines.append("%%EOF")

        full_pdf = end_obj6 + "\n".join(xref_lines).encode("latin-1")

        with open(output_path, "wb") as f:
            f.write(full_pdf)

        logger.info(f"Successfully generated PDF report ({len(full_pdf)} bytes) at {output_path.as_posix()}")
        return output_path
