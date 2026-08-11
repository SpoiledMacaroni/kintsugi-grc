"""
Kintsugi-GRC GUI Application & Interactive Compliance Dashboard
Provides a modern Desktop GUI (Tkinter/ttk) and Web GUI dashboard for selecting 
target directories, choosing industries, initiating real-time scans with progress bars,
sorting/filtering findings (All vs Violations Only), and exporting PDF audit reports.
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


class KintsugiAppTkinterGUI:
    """Native Desktop GUI Application built with Python tkinter/ttk."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Kintsugi-GRC Security & Compliance Scanner")
        self.root.geometry("1024x720")
        self.root.minsize(800, 600)

        self.target_dir_var = tk.StringVar(value=os.path.abspath("./synthetic_test_env"))
        self.industry_var = tk.StringVar(value="All Industries")
        self.filter_var = tk.StringVar(value="Violations Only")  # Default filter
        
        self.scan_summary: Optional[Dict[str, Any]] = None
        self.is_scanning = False

        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        """Configures clean UI styles and colors."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Header.TLabel", font=("Helvetica", 14, "bold"), foreground="#1a2e40")
        style.configure("Title.TLabel", font=("Helvetica", 18, "bold"), foreground="#0f2b48")
        style.configure("Score.TLabel", font=("Helvetica", 16, "bold"), foreground="#2e7d32")
        style.configure("Accent.TButton", font=("Helvetica", 10, "bold"), background="#1976d2", foreground="white")

    def _build_ui(self):
        """Constructs full Desktop GUI layout."""
        # Header Frame
        header_frame = ttk.Frame(self.root, padding=15)
        header_frame.pack(fill="x")

        ttk.Label(header_frame, text="Kintsugi-GRC Compliance Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header_frame, text="Automated Risk Detection, IAM Audit & Control Framework Mapping", font=("Helvetica", 9)).pack(anchor="w")
        ttk.Separator(self.root, orient="horizontal").pack(fill="x", px=15)

        # Control Panel Frame (Target Dir + Industry + Launch)
        control_frame = ttk.LabelFrame(self.root, text="Scan Configuration Target", padding=15)
        control_frame.pack(fill="x", padx=15, pady=10)

        # Target Dir Selector
        row1 = ttk.Frame(control_frame)
        row1.pack(fill="x", pady=5)
        ttk.Label(row1, text="Target Directory:", width=16, font=("Helvetica", 10, "bold")).pack(side="left")
        ttk.Entry(row1, textvariable=self.target_dir_var).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(row1, text="Browse...", command=self._browse_directory).pack(side="left")

        # Industry Dropdown & Launch Button
        row2 = ttk.Frame(control_frame)
        row2.pack(fill="x", pady=5)
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
        self.progress_frame = ttk.Frame(self.root, padding=(15, 5))
        self.progress_frame.pack(fill="x")

        self.lbl_progress = ttk.Label(self.progress_frame, text="Ready to scan.", font=("Helvetica", 9, "italic"))
        self.lbl_progress.pack(anchor="w")

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="determinate")
        self.progress_bar.pack(fill="x", pady=5)

        # Findings Results Section
        results_frame = ttk.LabelFrame(self.root, text="Scan Findings & Control Mappings", padding=10)
        results_frame.pack(fill="both", expand=True, padx=15, pady=10)

        # Filter Toolbar (All vs Violations Only & PDF Export)
        toolbar = ttk.Frame(results_frame)
        toolbar.pack(fill="x", pady=5)

        ttk.Label(toolbar, text="Filter View:", font=("Helvetica", 9, "bold")).pack(side="left", padx=5)
        ttk.Radiobutton(toolbar, text="Violations Only", value="Violations Only", variable=self.filter_var, command=self._update_findings_table).pack(side="left", padx=5)
        ttk.Radiobutton(toolbar, text="All Findings (Inc. Pass)", value="All Findings", variable=self.filter_var, command=self._update_findings_table).pack(side="left", padx=5)

        self.btn_pdf = ttk.Button(toolbar, text="📄 Export PDF Report", command=self._export_pdf, state="disabled")
        self.btn_pdf.pack(side="right", padx=5)

        self.lbl_score = ttk.Label(toolbar, text="Score: --%", style="Score.TLabel")
        self.lbl_score.pack(side="right", padx=15)

        # Findings Treeview Table
        tree_scroll = ttk.Scrollbar(results_frame)
        tree_scroll.pack(side="right", fill="y")

        columns = ("severity", "rule_id", "title", "file_path", "controls")
        self.tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll.set,
            selectmode="browse"
        )
        tree_scroll.config(command=self.tree.yview)

        self.tree.heading("severity", text="Severity")
        self.tree.heading("rule_id", text="Rule ID")
        self.tree.heading("title", text="Finding Title")
        self.tree.heading("file_path", text="File Path")
        self.tree.heading("controls", text="GRC Controls")

        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("rule_id", width=160, anchor="w")
        self.tree.column("title", width=250, anchor="w")
        self.tree.column("file_path", width=250, anchor="w")
        self.tree.column("controls", width=180, anchor="w")

        self.tree.pack(fill="both", expand=True)

        # Tag colors for Treeview
        self.tree.tag_configure("CRITICAL", foreground="#b71c1c", font=("Helvetica", 9, "bold"))
        self.tree.tag_configure("HIGH", foreground="#e65100", font=("Helvetica", 9, "bold"))
        self.tree.tag_configure("MEDIUM", foreground="#f57f17", font=("Helvetica", 9))
        self.tree.tag_configure("PASS", foreground="#2e7d32", font=("Helvetica", 9))

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
            # Simulate smooth progress bar ticks
            for pct in range(5, 30, 5):
                time.sleep(0.05)
                self.root.after(0, self._update_progress, pct, f"Parsing controls & scanning target {target_dir.name}...")

            audit_log = target_dir / "kintsugi_scanner_audit.log"
            audit_logger = ScannerAuditLogger(audit_log)
            audit_logger.initialize()

            control_reg = ControlRegistry()
            control_reg.load()

            for pct in range(35, 75, 10):
                time.sleep(0.05)
                self.root.after(0, self._update_progress, pct, "Auditing permissions, encryption & system configs...")

            engine = ScannerEngine(target_dir, control_reg, audit_logger)
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
        self.lbl_score.config(text=f"Risk Score: {score}%")

        self._update_findings_table()

    def _on_scan_error(self, err_msg: str):
        """Callback executed on GUI thread if scan errors out."""
        self.is_scanning = False
        self.btn_launch.config(state="normal")
        self.lbl_progress.config(text="Scan failed.")
        messagebox.showerror("Scan Error", f"An error occurred during scan: {err_msg}")

    def _update_findings_table(self):
        """Populates Treeview table based on selected filter (All vs Violations Only)."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.scan_summary:
            return

        findings = self.scan_summary.get("findings", [])
        filter_mode = self.filter_var.get()

        for f in findings:
            severity = f.get("severity", "INFO")

            # Apply filter
            if filter_mode == "Violations Only" and severity == "PASS":
                continue

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
