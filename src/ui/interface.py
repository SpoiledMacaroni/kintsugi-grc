"""
Kintsugi-GRC GUI Application & Interactive Compliance Dashboard
Provides a modern Desktop GUI (Tkinter/ttk) with target directory selection, 
industry focus dropdown, real-time progress bar, violations filter, risk score tooltip hover,
expandable full finding inspection details panel, and PDF compliance export.
"""

import json
import logging
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.mapping.controls import ControlRegistry
from src.output.pdf_exporter import PDFComplianceExporter
from src.output.reporter import ScanReporter
from src.placeholders.rag_pipeline import RAGPipelineClient
from src.scanner.audit import ScannerAuditLogger
from src.scanner.engine import ScannerEngine

logger = logging.getLogger("kintsugi_ui")


class ToolTip:
    """Hover tooltip for Tkinter widgets."""

    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw,
            text=self.text,
            justify="left",
            background="#1e293b",
            foreground="#f8fafc",
            relief="solid",
            borderwidth=1,
            font=("Helvetica", 9, "normal"),
            padx=10,
            pady=8
        )
        label.pack(ipadx=1)

    def hide_tip(self, event=None):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()


class KintsugiAppTkinterGUI:
    """Native Desktop GUI Application built with Python tkinter/ttk."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Kintsugi-GRC Security & Compliance Scanner")
        self.root.geometry("1080x780")
        self.root.minsize(850, 650)

        self.target_dir_var = tk.StringVar(value=os.path.abspath("./synthetic_test_env"))
        self.industry_var = tk.StringVar(value="All Industries")
        self.filter_var = tk.StringVar(value="Violations Only")

        self.scan_summary: Optional[Dict[str, Any]] = None
        self.displayed_findings: List[Dict[str, Any]] = []
        self.is_scanning = False

        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        """Configures UI styles and color palettes."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Header.TLabel", font=("Helvetica", 14, "bold"), foreground="#1a2e40")
        style.configure("Title.TLabel", font=("Helvetica", 18, "bold"), foreground="#0f2b48")
        style.configure("Score.TLabel", font=("Helvetica", 14, "bold"), foreground="#2e7d32")
        style.configure("Accent.TButton", font=("Helvetica", 10, "bold"), background="#1976d2", foreground="white")

    def _build_ui(self):
        """Constructs full Desktop GUI layout."""
        # Header Frame
        header_frame = ttk.Frame(self.root, padding=12)
        header_frame.pack(fill="x")

        ttk.Label(header_frame, text="Kintsugi-GRC Compliance Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Automated Risk Detection, IAM Audit & Industry Control Framework Mapping", font=("Helvetica", 9)).pack(anchor="w")
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", padx=15)

        # Control Panel Frame (Target Dir + Industry + Launch)
        control_frame = ttk.LabelFrame(self.root, text="Scan Configuration Target", padding=12)
        control_frame.pack(fill="x", padx=15, pady=8)

        # Target Dir Selector
        row1 = ttk.Frame(control_frame)
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Target Directory:", width=16, font=("Helvetica", 10, "bold")).pack(side="left")
        ttk.Entry(row1, textvariable=self.target_dir_var).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(row1, text="Browse...", command=self._browse_directory).pack(side="left")

        # Industry Dropdown & Launch Button
        row2 = ttk.Frame(control_frame)
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Industry Focus:", width=16, font=("Helvetica", 10, "bold")).pack(side="left")

        industry_cb = ttk.Combobox(
            row2,
            textvariable=self.industry_var,
            values=["All Industries", "Healthcare", "Merchant / E-Commerce", "Finance / Treasury", "Banking / SWIFT"],
            state="readonly",
            width=25
        )
        industry_cb.pack(side="left", padx=5)

        self.btn_launch = ttk.Button(row2, text="🚀 Launch Scan", style="Accent.TButton", command=self._start_scan_thread)
        self.btn_launch.pack(side="right", padx=5)

        # Progress Bar Frame
        self.progress_frame = ttk.Frame(self.root, padding=(15, 4))
        self.progress_frame.pack(fill="x")

        self.lbl_progress = ttk.Label(self.progress_frame, text="Ready to scan.", font=("Helvetica", 9, "italic"))
        self.lbl_progress.pack(anchor="w")

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="determinate")
        self.progress_bar.pack(fill="x", pady=4)

        # Findings Results Section
        results_frame = ttk.LabelFrame(self.root, text="Scan Findings & Control Mappings", padding=10)
        results_frame.pack(fill="both", expand=True, padx=15, pady=6)

        # Filter Toolbar & Risk Score Tooltip
        toolbar = ttk.Frame(results_frame)
        toolbar.pack(fill="x", pady=4)

        ttk.Label(toolbar, text="Filter View:", font=("Helvetica", 9, "bold")).pack(side="left", padx=5)
        ttk.Radiobutton(toolbar, text="Violations Only", value="Violations Only", variable=self.filter_var, command=self._update_findings_table).pack(side="left", padx=5)
        ttk.Radiobutton(toolbar, text="All Findings (Inc. Pass)", value="All Findings", variable=self.filter_var, command=self._update_findings_table).pack(side="left", padx=5)

        self.btn_pdf = ttk.Button(toolbar, text="📄 Export PDF Report", command=self._export_pdf, state="disabled")
        self.btn_pdf.pack(side="right", padx=5)

        # Risk Score Label & Hover Tooltip
        self.lbl_score = ttk.Label(toolbar, text="Score: --%", style="Score.TLabel")
        self.lbl_score.pack(side="right", padx=(10, 5))

        btn_info = ttk.Button(toolbar, text="❓", width=3, command=self._show_score_modal)
        btn_info.pack(side="right", padx=2)

        tooltip_text = (
            "GRC Security Health Index (0-100%)\n"
            "Calculated as the weighted ratio of passing controls vs violations:\n"
            "• PASS: 100% credit\n"
            "• MEDIUM: 50% credit\n"
            "• HIGH: 25% credit\n"
            "• CRITICAL: 0% credit"
        )
        ToolTip(self.lbl_score, tooltip_text)
        ToolTip(btn_info, "Click to view full Risk Score formula breakdown.")

        # Findings Treeview Table
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side="right", fill="y")

        columns = ("severity", "rule_id", "title", "file_path", "controls")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll.set,
            selectmode="browse",
            height=8
        )
        tree_scroll.config(command=self.tree.yview)

        self.tree.heading("severity", text="Severity")
        self.tree.heading("rule_id", text="Rule ID")
        self.tree.heading("title", text="Finding Title")
        self.tree.heading("file_path", text="File Path")
        self.tree.heading("controls", text="GRC Controls")

        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("rule_id", width=160, anchor="w")
        self.tree.column("title", width=240, anchor="w")
        self.tree.column("file_path", width=250, anchor="w")
        self.tree.column("controls", width=180, anchor="w")

        self.tree.pack(fill="both", expand=True)

        # Tag colors for Treeview
        self.tree.tag_configure("CRITICAL", foreground="#b71c1c", font=("Helvetica", 9, "bold"))
        self.tree.tag_configure("HIGH", foreground="#e65100", font=("Helvetica", 9, "bold"))
        self.tree.tag_configure("MEDIUM", foreground="#d97706", font=("Helvetica", 9))
        self.tree.tag_configure("PASS", foreground="#15803d", font=("Helvetica", 9))

        # Event Binding for Expandable Details Panel
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        # Expandable Detail Inspection Panel
        detail_frame = ttk.LabelFrame(results_frame, text="🔍 Selected Finding Full Inspection Detail", padding=8)
        detail_frame.pack(fill="both", expand=True, pady=(8, 0))

        detail_scroll = ttk.Scrollbar(detail_frame)
        detail_scroll.pack(side="right", fill="y")

        self.txt_detail = tk.Text(
            detail_frame,
            wrap="word",
            height=7,
            font=("Consolas", 9),
            yscrollcommand=detail_scroll.set,
            background="#0f172a",
            foreground="#f8fafc",
            insertbackground="white",
            padx=8,
            pady=8
        )
        detail_scroll.config(command=self.txt_detail.yview)
        self.txt_detail.pack(fill="both", expand=True)

        # Configure Text Tags for Custom Highlighting
        self.txt_detail.tag_configure("TITLE", font=("Helvetica", 11, "bold"), foreground="#38bdf8")
        self.txt_detail.tag_configure("CRITICAL", font=("Helvetica", 10, "bold"), foreground="#ef4444")
        self.txt_detail.tag_configure("HIGH", font=("Helvetica", 10, "bold"), foreground="#f97316")
        self.txt_detail.tag_configure("MEDIUM", font=("Helvetica", 10, "bold"), foreground="#eab308")
        self.txt_detail.tag_configure("PASS", font=("Helvetica", 10, "bold"), foreground="#22c55e")
        self.txt_detail.tag_configure("LABEL", font=("Helvetica", 9, "bold"), foreground="#94a3b8")
        self.txt_detail.tag_configure("VALUE", font=("Consolas", 9), foreground="#e2e8f0")
        self.txt_detail.tag_configure("CONTROL", font=("Helvetica", 9, "bold"), foreground="#a855f7")

        self._set_detail_text("Select any finding in the table above to expand and view un-truncated rule details, technical parameters, mapped GRC controls, and RAG AI remediation steps.")

    def _set_detail_text(self, text: str):
        """Sets text in the detail inspection panel."""
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        self.txt_detail.insert("1.0", text)
        self.txt_detail.config(state="disabled")

    def _show_score_modal(self):
        """Displays popup modal explaining Risk Score calculation."""
        messagebox.showinfo(
            "GRC Security Health Index Explanation",
            "GRC Security Health Index (Compliance Score):\n\n"
            "Calculated as the weighted ratio of passing controls vs violations across all evaluated target files:\n\n"
            "• PASS Findings    : 100% Credit (1.0)\n"
            "• MEDIUM Findings  : 50% Credit (0.5)\n"
            "• HIGH Findings    : 25% Credit (0.25)\n"
            "• CRITICAL Findings: 0% Credit (0.0)\n\n"
            "Formula:\n"
            "Score = (PASS*1.0 + MEDIUM*0.5 + HIGH*0.25) / Total_Checks * 100%"
        )

    def _browse_directory(self):
        """Opens native file directory chooser."""
        chosen = filedialog.askdirectory(initialdir=self.target_dir_var.get())
        if chosen:
            self.target_dir_var.set(chosen)

    def _start_scan_thread(self):
        """Launches scan in background thread to keep GUI smooth and responsive."""
        if self.is_scanning:
            return

        target = Path(self.target_dir_var.get()).resolve()
        if not target.exists():
            messagebox.showerror("Invalid Directory", f"Target directory '{target.as_posix()}' does not exist.")
            return

        self.is_scanning = True
        self.btn_launch.config(state="disabled")
        self.btn_pdf.config(state="disabled")
        self.progress_bar["value"] = 0
        self.lbl_progress.config(text="Initializing scan engine & loading GRC control schemas...")

        threading.Thread(target=self._run_scan_worker, args=(target,), daemon=True).start()

    def _run_scan_worker(self, target_dir: Path):
        """Worker thread executing ScannerEngine and updating GUI progress."""
        try:
            for pct in range(5, 30, 5):
                time.sleep(0.05)
                self.root.after(0, self._update_progress, pct, f"Parsing controls & scanning target {target_dir.name}...")

            audit_log = target_dir / "kintsugi_scanner_audit.log"
            audit_logger = ScannerAuditLogger(audit_log)
            audit_logger.initialize()

            control_reg = ControlRegistry()
            control_reg.load()

            industry = self.industry_var.get()
            engine = ScannerEngine(target_dir, control_reg, audit_logger, industry=industry)
            summary = engine.run_scan()

            rag_client = RAGPipelineClient()
            rag_client.connect()
            for f in summary.get("findings", []):
                if f.get("severity") in ["CRITICAL", "HIGH"]:
                    f["rag_ai_remediation"] = rag_client.query_compliance_remediation(f)

            audit_logger.finalize(summary["total_files_scanned"], summary["total_findings"])

            for pct in range(80, 101, 10):
                time.sleep(0.03)
                self.root.after(0, self._update_progress, pct, "Finalizing report...")

            self.root.after(0, self._on_scan_complete, summary)

        except Exception as e:
            logger.error(f"Scan worker failed: {e}")
            self.root.after(0, self._on_scan_error, str(e))

    def _update_progress(self, val: int, msg: str):
        """Updates progress bar value and status text on GUI thread."""
        self.progress_bar["value"] = val
        self.lbl_progress.config(text=f"{val}% - {msg}")

    def _on_scan_complete(self, summary: Dict[str, Any]):
        """Callback executed on GUI thread when scan finishes."""
        self.scan_summary = summary
        self.is_scanning = False
        self.btn_launch.config(state="normal")
        self.btn_pdf.config(state="normal")
        self.lbl_progress.config(text=f"Scan Complete! Scanned {summary['total_files_scanned']} files in {summary['target_directory']}")

        score = summary.get("compliance_score", 0)
        self.lbl_score.config(text=f"Score: {score}%")

        self._update_findings_table()

    def _on_scan_error(self, err_msg: str):
        """Callback executed on GUI thread if scan errors out."""
        self.is_scanning = False
        self.btn_launch.config(state="normal")
        self.lbl_progress.config(text="Scan failed.")
        messagebox.showerror("Scan Error", f"An error occurred during scan: {err_msg}")

    def _update_findings_table(self):
        """Populates Treeview table based on selected filter (All vs Violations Only)."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.displayed_findings.clear()
        if not self.scan_summary:
            return

        findings = self.scan_summary.get("findings", [])
        filter_mode = self.filter_var.get()

        for f in findings:
            severity = f.get("severity", "INFO")

            if filter_mode == "Violations Only" and severity == "PASS":
                continue

            self.displayed_findings.append(f)
            rule_id = f.get("rule_id", "N/A")
            title = f.get("title", "Finding")
            file_path = f.get("file_path", "N/A")
            mappings = f.get("framework_mappings", [])
            controls_str = ", ".join(f"{m.get('framework')}:{m.get('control_id')}" for m in mappings[:2])

            self.tree.insert(
                "",
                "end",
                values=(severity, rule_id, title, file_path, controls_str),
                tags=(severity,)
            )

    def _on_tree_select(self, event=None):
        """Populates expandable detail panel when user selects a finding row."""
        selected = self.tree.selection()
        if not selected:
            return

        index = self.tree.index(selected[0])
        if index < 0 or index >= len(self.displayed_findings):
            return

        finding = self.displayed_findings[index]
        self._populate_detail_panel(finding)

    def _on_tree_double_click(self, event=None):
        """Opens standalone popup dialog with full details on double-click."""
        selected = self.tree.selection()
        if not selected:
            return

        index = self.tree.index(selected[0])
        if index < 0 or index >= len(self.displayed_findings):
            return

        finding = self.displayed_findings[index]
        self._show_finding_dialog(finding)

    def _populate_detail_panel(self, f: Dict[str, Any]):
        """Renders rich formatted un-truncated finding details in the lower panel."""
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")

        severity = f.get("severity", "INFO")
        title = f.get("title", "Security Finding")
        rule_id = f.get("rule_id", "N/A")
        file_path = f.get("file_path", "N/A")
        desc = f.get("description", "No description available.")
        details = f.get("details", {})
        mappings = f.get("framework_mappings", [])
        remediation = f.get("rag_ai_remediation", "")

        self.txt_detail.insert("end", f"[{severity}] ", severity)
        self.txt_detail.insert("end", f"{title}\n", "TITLE")
        self.txt_detail.insert("end", f"{'='*80}\n")

        self.txt_detail.insert("end", "• File Path   : ", "LABEL")
        self.txt_detail.insert("end", f"{file_path}\n", "VALUE")

        self.txt_detail.insert("end", "• Rule ID     : ", "LABEL")
        self.txt_detail.insert("end", f"{rule_id}\n", "VALUE")

        self.txt_detail.insert("end", "• Description : ", "LABEL")
        self.txt_detail.insert("end", f"{desc}\n", "VALUE")

        if details:
            self.txt_detail.insert("end", "• Technical Details : ", "LABEL")
            self.txt_detail.insert("end", f"{json.dumps(details)}\n", "VALUE")

        if mappings:
            self.txt_detail.insert("end", "• GRC Framework Controls Applied:\n", "LABEL")
            for m in mappings:
                fw = m.get("framework", "GRC")
                cid = m.get("control_id", "N/A")
                ctitle = m.get("title", "Requirement")
                st = m.get("status", "REVIEW")
                self.txt_detail.insert("end", f"   - [{fw}] {cid}: {ctitle} ({st})\n", "CONTROL")

        if remediation:
            self.txt_detail.insert("end", "• AI RAG Remediation Guidance:\n", "LABEL")
            self.txt_detail.insert("end", f"   {remediation}\n", "VALUE")

        self.txt_detail.config(state="disabled")

    def _show_finding_dialog(self, f: Dict[str, Any]):
        """Opens a standalone top-level dialog with complete finding information."""
        top = tk.Toplevel(self.root)
        top.title(f"Finding Detail: {f.get('rule_id')}")
        top.geometry("700x500")

        txt = tk.Text(top, wrap="word", font=("Consolas", 10), background="#0f172a", foreground="#f8fafc", padx=10, pady=10)
        txt.pack(fill="both", expand=True)

        info_lines = [
            f"FINDING DETAILED AUDIT REPORT",
            "=" * 60,
            f"Title        : {f.get('title')}",
            f"Severity     : {f.get('severity')}",
            f"Rule ID      : {f.get('rule_id')}",
            f"File Path    : {f.get('file_path')}",
            f"Description  : {f.get('description')}",
            f"Details      : {json.dumps(f.get('details', {}), indent=2)}",
            "\nMAPPED GRC CONTROLS:",
        ]
        for m in f.get("framework_mappings", []):
            info_lines.append(f"  - [{m.get('framework')}] {m.get('control_id')}: {m.get('title')} ({m.get('status')})")

        if f.get("rag_ai_remediation"):
            info_lines.append(f"\nAI RAG REMEDIATION:\n  {f.get('rag_ai_remediation')}")

        txt.insert("1.0", "\n".join(info_lines))
        txt.config(state="disabled")

    def _export_pdf(self):
        """Triggers PDF export of current scan summary."""
        if not self.scan_summary:
            messagebox.showwarning("No Data", "Please launch a scan first before exporting PDF.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Documents", "*.pdf")],
            initialfile="scan_report.pdf"
        )
        if save_path:
            out_pdf = Path(save_path)
            PDFComplianceExporter.generate_pdf_report(self.scan_summary, out_pdf)
            messagebox.showinfo("PDF Exported", f"Successfully generated compliance PDF report:\n{out_pdf.as_posix()}")


def launch_tkinter_gui():
    """Launches native Tkinter Desktop GUI application."""
    root = tk.Tk()
    app = KintsugiAppTkinterGUI(root)
    root.mainloop()
