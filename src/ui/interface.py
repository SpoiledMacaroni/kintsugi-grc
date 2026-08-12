"""
Kintsugi-GRC Native Desktop UI
Provides a bright, modern, responsive security and compliance protection center interface.
Prompts user for target directory monitoring with rich hover tooltips, highlights non-intrusive 
GRC domain controls, compiles a running ledger of findings with interactive clickable file paths 
that reveal files in native system Explorer/Finder, and runs a dynamic background watcher that 
re-evaluates file edits and automatically revises risk scores and clears findings upon remediation.
"""

import json
import logging
import os
import subprocess
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
from src.rag.pipeline import RAGPipelineClient
from src.scanner.audit import ScannerAuditLogger
from src.scanner.engine import ScannerEngine
from src.scanner.watcher import DynamicDirectoryWatcher

logger = logging.getLogger("kintsugi_ui")


def reveal_in_file_explorer(file_path: Path):
    """Reveals the target file in native system file explorer (macOS Finder / Windows Explorer)."""
    abs_path = file_path.resolve()
    if not abs_path.exists():
        return
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", str(abs_path)])
        elif sys.platform == "win32":
            subprocess.run(["explorer", "/select,", str(abs_path)])
        else:
            subprocess.run(["xdg-open", str(abs_path.parent)])
    except Exception as e:
        logger.error(f"Failed to open file in system explorer: {e}")


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
            background="#0f172a",
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
    """Windows Security-like Native Desktop GUI Application."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Kintsugi GRC - Security & Compliance Monitoring Center")
        self.root.geometry("1180x820")
        self.root.minsize(920, 680)

        # Main window background: Bright off-white / light slate (#f8fafc)
        self.root.configure(background="#f8fafc")

        self.target_dir_var = tk.StringVar(value=os.path.abspath("./synthetic_test_env"))
        self.custom_policy_var = tk.StringVar(value="")
        self.industry_var = tk.StringVar(value="All Industries")
        self.filter_var = tk.StringVar(value="Violations Only")

        self.scan_summary: Optional[Dict[str, Any]] = None
        self.displayed_findings: List[Dict[str, Any]] = []
        self.active_pie_severity_filter: Optional[str] = None
        self.is_scanning = False
        self.is_monitoring = False

        self.active_engine: Optional[ScannerEngine] = None
        self.active_watcher: Optional[DynamicDirectoryWatcher] = None
        self.rag_client: Optional[RAGPipelineClient] = None

        self._build_styles()
        self._build_ui()

    def _build_styles(self):
        """Configures clean, bright Windows Security style typography and widgets."""
        style = ttk.Style()
        style.theme_use("clam")

        # Base Palette
        style.configure(".", background="#f8fafc", foreground="#0f172a", font=("Helvetica", 10))
        style.configure("TFrame", background="#f8fafc")
        style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)

        # Buttons
        style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"), background="#0284c7", foreground="white", padding=(4, 2))
        style.map("Primary.TButton", background=[("active", "#0369a1")])

        style.configure("Secondary.TButton", font=("Segoe UI", 9), background="#e2e8f0", foreground="#0f172a", padding=(4, 2))
        style.map("Secondary.TButton", background=[("active", "#cbd5e1")])

        style.configure("Danger.TButton", font=("Segoe UI", 9, "bold"), background="#ef4444", foreground="white", padding=(4, 2))

    def _build_ui(self):
        """Constructs responsive Windows Security style dashboard layout using standard tk containers for colors."""
        main_container = tk.Frame(self.root, bg="#f8fafc", padx=16, pady=16)
        main_container.pack(fill="both", expand=True)

        # ---------------------------------------------------------------------
        # 1. WINDOWS SECURITY HERO HEADER CARD
        # ---------------------------------------------------------------------
        hero_card = tk.Frame(main_container, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=14, pady=14)
        hero_card.pack(fill="x", pady=(0, 10))

        hero_left = tk.Frame(hero_card, bg="#ffffff")
        hero_left.pack(side="left", fill="both", expand=True)

        lbl_shield = tk.Label(hero_left, text="🛡️", font=("Segoe UI Emoji", 28), bg="#ffffff")
        lbl_shield.pack(side="left", padx=(0, 12))
        ToolTip(lbl_shield, "Kintsugi GRC Dynamic Protection Engine actively monitoring directory security standards.")

        title_box = tk.Frame(hero_left, bg="#ffffff")
        title_box.pack(side="left", anchor="w")
        tk.Label(title_box, text="Security & Compliance Protection", font=("Segoe UI", 16, "bold"), fg="#0f172a", bg="#ffffff").pack(anchor="w")
        tk.Label(title_box, text="Dynamic File Watcher & Automated GRC Control Audit (HIPAA, PCI DSS, NIST)", font=("Segoe UI", 9), fg="#64748b", bg="#ffffff").pack(anchor="w")

        # Security Status Badge Ring
        self.hero_status_lbl = tk.Label(
            hero_card,
            text="🟢 Ready to Monitor",
            font=("Segoe UI", 11, "bold"),
            fg="#15803d",
            bg="#dcfce7",
            padx=10,
            pady=6
        )
        self.hero_status_lbl.pack(side="right", padx=10)
        ToolTip(self.hero_status_lbl, "Displays dynamic system security health. Green = Protection Active, Red/Orange = Action Required.")

        # ---------------------------------------------------------------------
        # 2. TARGET DIRECTORY SELECTION & CONTROL CONFIGURATION CARD
        # ---------------------------------------------------------------------
        config_card = tk.Frame(main_container, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=14, pady=14)
        config_card.pack(fill="x", pady=(0, 10))

        tk.Label(config_card, text="🎯 Monitoring Target & Industry Framework", font=("Segoe UI", 11, "bold"), fg="#0284c7", bg="#ffffff").pack(anchor="w", pady=(0, 8))

        # Target Directory Selector Row
        row_dir = tk.Frame(config_card, bg="#ffffff")
        row_dir.pack(fill="x", pady=2)
        tk.Label(row_dir, text="Target Directory to Monitor:", font=("Segoe UI", 9, "bold"), fg="#0f172a", bg="#ffffff", width=22, anchor="w").pack(side="left")
        
        ent_dir = ttk.Entry(row_dir, textvariable=self.target_dir_var, font=("Consolas", 9))
        ent_dir.pack(side="left", fill="x", expand=True, padx=4)
        ToolTip(ent_dir, "Select target codebase or environment directory to monitor.")

        btn_browse = ttk.Button(row_dir, text="📁 Browse...", style="Secondary.TButton", command=self._browse_directory)
        btn_browse.pack(side="left", padx=2)
        ToolTip(btn_browse, "Browse system folders to pick target directory.")

        btn_open_finder = ttk.Button(row_dir, text="📂 Open Folder", style="Secondary.TButton", command=self._open_target_in_explorer)
        btn_open_finder.pack(side="left", padx=2)
        ToolTip(btn_open_finder, "Opens target folder in native macOS Finder / Windows Explorer.")

        # Custom JSON Policy File Selector Row
        row_policy = tk.Frame(config_card, bg="#ffffff")
        row_policy.pack(fill="x", pady=2)
        tk.Label(row_policy, text="Custom Security Policy (JSON):", font=("Segoe UI", 9, "bold"), fg="#0f172a", bg="#ffffff", width=22, anchor="w").pack(side="left")

        ent_policy = ttk.Entry(row_policy, textvariable=self.custom_policy_var, font=("Consolas", 9))
        ent_policy.pack(side="left", fill="x", expand=True, padx=4)
        ToolTip(ent_policy, "Upload a custom JSON company policy document into the vector engine.")

        btn_upload_policy = ttk.Button(row_policy, text="📄 Upload...", style="Secondary.TButton", command=self._upload_custom_policy)
        btn_upload_policy.pack(side="left", padx=2)
        ToolTip(btn_upload_policy, "Browse and upload a custom JSON policy file.")

        self.lbl_policy_status = tk.Label(row_policy, text="[No Custom Policy Loaded]", font=("Segoe UI", 8, "italic"), fg="#64748b", bg="#ffffff")
        self.lbl_policy_status.pack(side="left", padx=4)

        # Industry Dropdown & Action Controls Row
        row_act = tk.Frame(config_card, bg="#ffffff")
        row_act.pack(fill="x", pady=(4, 2))

        tk.Label(row_act, text="Industry Citation Scope:", font=("Segoe UI", 9, "bold"), fg="#0f172a", bg="#ffffff", width=22, anchor="w").pack(side="left")
        cb_ind = ttk.Combobox(
            row_act,
            textvariable=self.industry_var,
            values=["All Industries", "Healthcare", "Merchant / E-Commerce", "Finance / Treasury", "Banking / SWIFT"],
            state="readonly",
            width=18
        )
        cb_ind.pack(side="left", padx=4)
        ToolTip(cb_ind, "Filters reported framework citations. e.g. Healthcare reports HIPAA §164.312 only.")

        # Start / Stop Monitoring Buttons
        self.btn_start = ttk.Button(row_act, text="▶ Start Monitoring", style="Primary.TButton", command=self._toggle_monitoring)
        self.btn_start.pack(side="right", padx=2)
        ToolTip(self.btn_start, "Launches background watcher to actively monitor directory changes.")

        self.btn_pdf = ttk.Button(row_act, text="📄 Export PDF", style="Secondary.TButton", command=self._export_pdf, state="disabled")
        self.btn_pdf.pack(side="right", padx=2)

        # ---------------------------------------------------------------------
        # 3. NON-INTRUSIVE DOMAIN CONTROL BADGES
        # ---------------------------------------------------------------------
        domain_card = tk.Frame(config_card, bg="#ffffff")
        domain_card.pack(fill="x", pady=(10, 0))

        tk.Label(domain_card, text="Addressed Control Domains:", font=("Segoe UI", 9, "bold"), fg="#64748b", bg="#ffffff").pack(side="left", padx=(0, 8))

        domains = [
            (
                "🔑 01.02 / 01.c: Privilege Management",
                "HITRUST CSF Ref 01.02, 01.c (Access Control) - Governs identity-aware, least-privilege enforcement of access to systems and data, including authorization definition, user/group permission bitmasks, and periodic review."
            ),
            (
                "🛡️ 06.01 / 06.d: Data Protection & Privacy",
                "HITRUST CSF Ref 06.01, 06.d (Data Protection & Privacy) - Governs organizational compliance with privacy protocols and protection of sensitive data at rest (PHI, credit cards, SSNs) via strong AES-256 cryptography and secure media sanitization."
            ),
            (
                "⚙️ 10.06 / 10.m: Tech Vulnerability Control",
                "HITRUST CSF Ref 10.06, 10.m (Configuration & Vulnerability Management) - Governs secure configuration, system hardening, and control of technical vulnerabilities. Enforces strong SSH Protocol 2, TLS 1.2/1.3 encryption, and password rotation."
            ),
            (
                "📦 09.07 / 09.q: Media & Info Handling",
                "HITRUST CSF Ref 09.07, 09.q (Information Handling) - Governs information handling, raw compressed data streams, and media storage security procedures to safeguard sensitive data from unauthorized interception or block pattern leaks."
            ),
            (
                "📋 09.10 / 10.aa: Monitoring & Audit Logging",
                "HITRUST CSF Ref 09.10, 10.aa (Audit Logging and Monitoring) - Governs the generation, protection, and review of audit logs. Enforces strict file permission controls (0o600) on /var/log/audit trails to prevent log tampering or erasure."
            )
        ]
        for name, tip in domains:
            lbl_pill = tk.Label(domain_card, text=name, font=("Segoe UI", 8, "bold"), fg="#0369a1", bg="#e0f2fe", padx=6, pady=3)
            lbl_pill.pack(side="left", padx=2)
            ToolTip(lbl_pill, tip)

        # ---------------------------------------------------------------------
        # 3. EXECUTIVE DASHBOARD: PIE CHART & TOP 3 ACTIONABLE ISSUES
        # ---------------------------------------------------------------------
        exec_card = tk.Frame(main_container, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=14, pady=10)
        exec_card.pack(fill="x", pady=(0, 10))

        tk.Label(exec_card, text="📈 Executive Summary & Priority Action Dashboard", font=("Segoe UI", 11, "bold"), fg="#0284c7", bg="#ffffff").pack(anchor="w", pady=(0, 6))

        exec_content = tk.Frame(exec_card, bg="#ffffff")
        exec_content.pack(fill="x")

        # Left Column: Pie Chart Canvas & Legend
        pie_frame = tk.Frame(exec_content, bg="#ffffff")
        pie_frame.pack(side="left", fill="y", padx=(0, 14))

        self.canvas_pie = tk.Canvas(pie_frame, width=140, height=120, bg="#ffffff", highlightthickness=0)
        self.canvas_pie.pack(side="left")

        self.pie_legend_frame = tk.Frame(pie_frame, bg="#ffffff")
        self.pie_legend_frame.pack(side="left", padx=(6, 0), fill="y")

        # Right Column: Top 3 Actionable Urgent Issues
        top3_frame = tk.Frame(exec_content, bg="#ffffff")
        top3_frame.pack(side="left", fill="both", expand=True)

        top3_hdr_row = tk.Frame(top3_frame, bg="#ffffff")
        top3_hdr_row.pack(fill="x", pady=(0, 4))

        self.lbl_top3_header = tk.Label(
            top3_hdr_row,
            text="🔥 Top 3 Priority Issues Requiring Remediation:",
            font=("Segoe UI", 9, "bold"),
            fg="#991b1b",
            bg="#ffffff"
        )
        self.lbl_top3_header.pack(side="left")

        self.btn_reset_pie_filter = ttk.Button(
            top3_hdr_row,
            text="🔄 Show All",
            style="Secondary.TButton",
            command=lambda: self._filter_top_3_by_severity("ALL")
        )
        ToolTip(self.btn_reset_pie_filter, "Reset pie chart filter to show overall top priority issues.")

        self.top3_container = tk.Frame(top3_frame, bg="#ffffff")
        self.top3_container.pack(fill="both", expand=True)

        self._draw_pie_chart({})
        self._update_top_3_issues([])

        # Status / Progress Bar Line
        self.progress_frame = tk.Frame(main_container, bg="#f8fafc")
        self.progress_frame.pack(fill="x", pady=4)

        self.lbl_progress = tk.Label(self.progress_frame, text="Ready. Select target directory and click START MONITORING.", font=("Segoe UI", 9, "italic"), fg="#475569", bg="#f8fafc")
        self.lbl_progress.pack(anchor="w")

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="determinate")
        self.progress_bar.pack(fill="x", pady=2)

        # ---------------------------------------------------------------------
        # 4. RUNNING LEDGER OF FINDINGS (INTERACTIVE TREEVIEW)
        # ---------------------------------------------------------------------
        ledger_card = tk.Frame(main_container, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=12, pady=12)
        ledger_card.pack(fill="both", expand=True, pady=(0, 10))

        # Ledger Header Toolbar
        ledger_tb = tk.Frame(ledger_card, bg="#ffffff")
        ledger_tb.pack(fill="x", pady=(0, 8))

        tk.Label(ledger_tb, text="📊 Live Interactive Findings Ledger", font=("Segoe UI", 11, "bold"), fg="#0284c7", bg="#ffffff").pack(side="left")

        tk.Label(ledger_tb, text="View:", font=("Segoe UI", 9, "bold"), fg="#0f172a", bg="#ffffff").pack(side="left", padx=(20, 5))
        tk.Radiobutton(ledger_tb, text="Violations Only", value="Violations Only", variable=self.filter_var, command=self._update_findings_table, bg="#ffffff", activebackground="#ffffff").pack(side="left", padx=4)
        tk.Radiobutton(ledger_tb, text="All Findings", value="All Findings", variable=self.filter_var, command=self._update_findings_table, bg="#ffffff", activebackground="#ffffff").pack(side="left", padx=4)

        # Risk Score Badge & Explanation Tooltip
        self.lbl_score = tk.Label(ledger_tb, text="Health Score: --%", font=("Segoe UI", 12, "bold"), fg="#0284c7", bg="#ffffff")
        self.lbl_score.pack(side="right", padx=(10, 0))

        btn_score_info = ttk.Button(ledger_tb, text="❓", width=3, style="Secondary.TButton", command=self._show_score_modal)
        btn_score_info.pack(side="right", padx=2)

        ToolTip(self.lbl_score, "GRC Security Health Index (0-100%). Weighted formula: PASS=100%, MEDIUM=50%, HIGH=25%, CRITICAL=0%.")
        ToolTip(btn_score_info, "Click to view full Risk Score calculation breakdown.")

        # Interactive Treeview Table
        tree_frame = tk.Frame(ledger_card, bg="#ffffff")
        tree_frame.pack(fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side="right", fill="y")

        columns = ("severity", "domain", "file_path", "rule_title", "remediation")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=tree_scroll.set,
            selectmode="browse",
            height=7
        )
        tree_scroll.config(command=self.tree.yview)

        self.tree.heading("severity", text="Status / Severity")
        self.tree.heading("domain", text="Control Domain")
        self.tree.heading("file_path", text="File Path (Double-Click to Open)")
        self.tree.heading("rule_title", text="Violated Control / Rule Title")
        self.tree.heading("remediation", text="Easy Remediation Recommendation")

        self.tree.column("severity", width=120, anchor="center")
        self.tree.column("domain", width=150, anchor="w")
        self.tree.column("file_path", width=320, anchor="w")
        self.tree.column("rule_title", width=260, anchor="w")
        self.tree.column("remediation", width=250, anchor="w")

        self.tree.pack(fill="both", expand=True)

        # Style Tags for Ledger Rows
        self.tree.tag_configure("CRITICAL", foreground="#991b1b", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("HIGH", foreground="#c2410c", font=("Segoe UI", 9, "bold"))
        self.tree.tag_configure("MEDIUM", foreground="#b45309", font=("Segoe UI", 9))
        self.tree.tag_configure("PASS", foreground="#15803d", font=("Segoe UI", 9))

        # Ledger Event Bindings
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        # ---------------------------------------------------------------------
        # 5. EXPANDABLE FINDING DETAIL & REMEDIATION PANEL
        # ---------------------------------------------------------------------
        detail_card = tk.Frame(main_container, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=12, pady=12)
        detail_card.pack(fill="both", expand=True)

        detail_tb = tk.Frame(detail_card, bg="#ffffff")
        detail_tb.pack(fill="x", pady=(0, 6))

        tk.Label(detail_tb, text="🔍 Selected Finding Details & AI Remediation Advisory", font=("Segoe UI", 11, "bold"), fg="#0284c7", bg="#ffffff").pack(side="left")

        self.btn_reveal_file = ttk.Button(detail_tb, text="📂 Reveal File in Explorer", style="Secondary.TButton", command=self._reveal_selected_file, state="disabled")
        self.btn_reveal_file.pack(side="right")
        ToolTip(self.btn_reveal_file, "Opens system Explorer / Finder focused directly on the selected file.")

        detail_scroll = ttk.Scrollbar(detail_card)
        detail_scroll.pack(side="right", fill="y")

        self.txt_detail = tk.Text(
            detail_card,
            wrap="word",
            height=6,
            font=("Consolas", 9),
            yscrollcommand=detail_scroll.set,
            background="#ffffff",
            foreground="#0f172a",
            relief="solid",
            borderwidth=1,
            padx=10,
            pady=10
        )
        detail_scroll.config(command=self.txt_detail.yview)
        self.txt_detail.pack(fill="both", expand=True)

        # Detail Text Formatting Tags
        self.txt_detail.tag_configure("TITLE", font=("Segoe UI", 11, "bold"), foreground="#0284c7")
        self.txt_detail.tag_configure("CRITICAL", font=("Segoe UI", 10, "bold"), foreground="#991b1b")
        self.txt_detail.tag_configure("HIGH", font=("Segoe UI", 10, "bold"), foreground="#c2410c")
        self.txt_detail.tag_configure("MEDIUM", font=("Segoe UI", 10, "bold"), foreground="#b45309")
        self.txt_detail.tag_configure("PASS", font=("Segoe UI", 10, "bold"), foreground="#15803d")
        self.txt_detail.tag_configure("LABEL", font=("Segoe UI", 9, "bold"), foreground="#475569")
        self.txt_detail.tag_configure("VALUE", font=("Consolas", 9), foreground="#0f172a")
        self.txt_detail.tag_configure("CMD", font=("Consolas", 9, "bold"), foreground="#0284c7", background="#f0f9ff")

        self._set_detail_text("Select any finding row in the running ledger above to inspect un-truncated details, technical parameters, exact GRC framework clauses, and RAG AI remediation commands.")

    # -------------------------------------------------------------------------
    # HELPER METHODS & WORKERS
    # -------------------------------------------------------------------------
    def _set_detail_text(self, text: str):
        """Sets formatted text in inspection panel."""
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")
        self.txt_detail.insert("1.0", text)
        self.txt_detail.config(state="disabled")

    def _browse_directory(self):
        """Opens native file directory chooser."""
        chosen = filedialog.askdirectory(initialdir=self.target_dir_var.get())
        if chosen:
            self.target_dir_var.set(chosen)

    def _open_target_in_explorer(self):
        """Opens target directory in macOS Finder / Windows Explorer."""
        target = Path(self.target_dir_var.get()).resolve()
        if target.exists():
            reveal_in_file_explorer(target)

    def _reveal_selected_file(self):
        """Reveals currently selected finding's file in macOS Finder / Explorer."""
        selected = self.tree.selection()
        if not selected:
            return
        index = self.tree.index(selected[0])
        if 0 <= index < len(self.displayed_findings):
            finding = self.displayed_findings[index]
            rel_path = finding.get("file_path", "")
            target_root = Path(self.target_dir_var.get()).resolve()
            full_path = (target_root / rel_path).resolve()
            if full_path.exists():
                reveal_in_file_explorer(full_path)
            else:
                reveal_in_file_explorer(target_root)

    def _show_score_modal(self):
        """Displays modal explaining Risk Score calculation."""
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

    def _toggle_monitoring(self):
        """Starts or stops dynamic background monitoring."""
        if self.is_monitoring:
            # Stop Monitoring
            if self.active_watcher:
                self.active_watcher.stop()
                self.active_watcher = None
            self.is_monitoring = False
            self.btn_start.config(text="▶ START MONITORING", style="Primary.TButton")
            self.hero_status_lbl.config(text="🟡 Monitoring Paused", fg="#b45309", bg="#fef3c7")
            self.lbl_progress.config(text="Background monitoring paused.")
        else:
            # Start Monitoring
            target = Path(self.target_dir_var.get()).resolve()
            if not target.exists():
                messagebox.showerror("Invalid Directory", f"Target directory '{target.as_posix()}' does not exist.")
                return

            self.is_monitoring = True
            self.is_scanning = True
            self.btn_start.config(text="⏹ STOP MONITORING", style="Danger.TButton")
            self.btn_pdf.config(state="disabled")
            self.progress_bar["value"] = 0
            self.lbl_progress.config(text="Initializing scanner engine & compiling running ledger...")

            threading.Thread(target=self._run_scan_worker, args=(target,), daemon=True).start()

    def _run_scan_worker(self, target_dir: Path):
        """Worker thread executing initial scan and starting dynamic watcher."""
        try:
            for pct in range(5, 30, 5):
                time.sleep(0.04)
                self.root.after(0, self._update_progress, pct, f"Parsing controls & scanning target {target_dir.name}...")

            audit_log = target_dir / "kintsugi_scanner_audit.log"
            audit_logger = ScannerAuditLogger(audit_log)
            audit_logger.initialize()

            control_reg = ControlRegistry()
            control_reg.load()

            industry = self.industry_var.get()
            self.active_engine = ScannerEngine(target_dir, control_reg, audit_logger, industry=industry)
            summary = self.active_engine.run_scan()

            self.rag_client = RAGPipelineClient()
            self.rag_client.connect()

            # Auto-vectorize custom policy if selected by user
            custom_policy_str = self.custom_policy_var.get().strip()
            if custom_policy_str and Path(custom_policy_str).exists():
                self.rag_client.ingest_and_vectorize_policy(Path(custom_policy_str))

            industry = self.industry_var.get()
            for f in summary.get("findings", []):
                if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                    advisory = self.rag_client.generate_advisory(f, industry=industry)
                    f["rag_advisory"] = advisory
                    f["rag_ai_remediation"] = advisory.get("remediation_command", "")

            audit_logger.finalize(summary["total_files_scanned"], summary["total_findings"])

            for pct in range(80, 101, 10):
                time.sleep(0.02)
                self.root.after(0, self._update_progress, pct, "Finalizing running ledger...")

            # Start Dynamic Directory Watcher
            self.active_watcher = DynamicDirectoryWatcher(
                target_dir=target_dir,
                on_file_changed=self._on_dynamic_file_changed,
                on_file_deleted=self._on_dynamic_file_deleted
            )
            self.active_watcher.start()

            self.root.after(0, self._on_scan_complete, summary)

        except Exception as e:
            logger.error(f"Scan worker failed: {e}")
            self.root.after(0, self._on_scan_error, str(e))

    def _on_dynamic_file_changed(self, abs_file_path: Path, event_type: str):
        """Callback triggered when watcher detects file edit, creation, or remediation."""
        if not self.active_engine:
            return

        updated_summary = self.active_engine.update_single_file(abs_file_path, event_type)

        # Enrich any new findings with RAG advisory
        if self.rag_client:
            industry = self.industry_var.get()
            for f in updated_summary.get("findings", []):
                if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"] and "rag_advisory" not in f:
                    advisory = self.rag_client.generate_advisory(f, industry=industry)
                    f["rag_advisory"] = advisory
                    f["rag_ai_remediation"] = advisory.get("remediation_command", "")

        rel_name = abs_file_path.name
        score = updated_summary.get("compliance_score", 0)

        # Check if file remediation resolved findings to PASS/None
        remaining = [f for f in updated_summary.get("findings", []) if abs_file_path.name in f.get("file_path", "") and f.get("severity") in ["CRITICAL", "HIGH"]]
        if len(remaining) == 0:
            status_text = f"✅ File Remediated: {rel_name} is now compliant! Health Score updated to {score}%."
        else:
            status_text = f"⚡ Dynamic Re-Scan ({event_type}): Updated {rel_name} (Health Score: {score}%)"

        self.root.after(0, self._apply_dynamic_update, updated_summary, status_text)

    def _on_dynamic_file_deleted(self, abs_file_path: Path, event_type: str):
        """Callback triggered when watcher detects file deletion."""
        if not self.active_engine:
            return

        updated_summary = self.active_engine.update_single_file(abs_file_path, event_type)
        score = updated_summary.get("compliance_score", 0)
        status_text = f"⚡ File Removed: Cleared findings for {abs_file_path.name} (Health Score: {score}%)"
        self.root.after(0, self._apply_dynamic_update, updated_summary, status_text)

    def _apply_dynamic_update(self, summary: Dict[str, Any], status_msg: str):
        """Updates GUI running ledger, risk score, and status badge dynamically."""
        self.scan_summary = summary
        score = summary.get("compliance_score", 0)
        self.lbl_score.config(text=f"Health Score: {score}%")
        self.lbl_progress.config(text=status_msg)

        # Update Hero Status Badge
        crits = summary.get("severity_counts", {}).get("CRITICAL", 0)
        highs = summary.get("severity_counts", {}).get("HIGH", 0)
        total_viols = crits + highs

        if total_viols == 0:
            self.hero_status_lbl.config(text="🟢 Protection Active - 100% Compliant", fg="#15803d", bg="#dcfce7")
        else:
            self.hero_status_lbl.config(text=f"⚠️ Action Required - {total_viols} Active Violations", fg="#b91c1c", bg="#fee2e2")

        self._draw_pie_chart(summary.get("severity_counts", {}))
        self._update_top_3_issues(summary.get("findings", []))
        self._update_findings_table()

    def _update_progress(self, val: int, msg: str):
        """Updates progress bar value and status text on GUI thread."""
        self.progress_bar["value"] = val
        self.lbl_progress.config(text=f"{val}% - {msg}")

    def _on_scan_complete(self, summary: Dict[str, Any]):
        """Callback executed on GUI thread when initial scan finishes."""
        self.scan_summary = summary
        self.is_scanning = False
        self.btn_pdf.config(state="normal")

        score = summary.get("compliance_score", 0)
        self.lbl_score.config(text=f"Health Score: {score}%")
        self.lbl_progress.config(text=f"Protection Active! Monitoring {summary['total_files_scanned']} files in {summary['target_directory']}")

        crits = summary.get("severity_counts", {}).get("CRITICAL", 0)
        highs = summary.get("severity_counts", {}).get("HIGH", 0)
        total_viols = crits + highs

        if total_viols == 0:
            self.hero_status_lbl.config(text="🟢 Protection Active - 100% Compliant", fg="#15803d", bg="#dcfce7")
        else:
            self.hero_status_lbl.config(text=f"⚠️ Action Required - {total_viols} Active Violations", fg="#b91c1c", bg="#fee2e2")

        self._draw_pie_chart(summary.get("severity_counts", {}))
        self._update_top_3_issues(summary.get("findings", []))
        self._update_findings_table()

    def _draw_pie_chart(self, sev_counts: Dict[str, int]):
        """Draws dynamic Tkinter pie chart of scan severities."""
        self.canvas_pie.delete("all")
        for w in self.pie_legend_frame.winfo_children():
            w.destroy()

        crits = sev_counts.get("CRITICAL", 0)
        highs = sev_counts.get("HIGH", 0)
        meds = sev_counts.get("MEDIUM", 0)
        passes = sev_counts.get("PASS", 0)
        total = crits + highs + meds + passes

        if total == 0:
            # Draw placeholder circle
            self.canvas_pie.create_oval(15, 10, 125, 110, fill="#f1f5f9", outline="#cbd5e1", width=2)
            self.canvas_pie.create_text(70, 60, text="No Scan\nData", font=("Segoe UI", 8, "bold"), fill="#64748b", justify="center")
            tk.Label(self.pie_legend_frame, text="Run scan to view\nseverity pie chart", font=("Segoe UI", 8, "italic"), fg="#64748b", bg="#ffffff").pack(anchor="w")
            return

        slice_data = [
            ("CRITICAL", crits, "#ef4444"),
            ("HIGH", highs, "#f97316"),
            ("MEDIUM", meds, "#eab308"),
            ("PASS", passes, "#22c55e"),
        ]

        current_angle = 90.0
        bbox = (10, 5, 125, 115)

        for label, count, color in slice_data:
            if count == 0:
                continue
            extent = (count / total) * 360.0
            arc_id = self.canvas_pie.create_arc(
                bbox[0], bbox[1], bbox[2], bbox[3],
                start=current_angle,
                extent=extent,
                fill=color,
                outline="#ffffff",
                width=1.5
            )
            self.canvas_pie.tag_bind(arc_id, "<Button-1>", lambda e, s=label: self._filter_top_3_by_severity(s))
            current_angle += extent

            pct = (count / total) * 100.0
            is_active = (self.active_pie_severity_filter == label)

            row = tk.Frame(self.pie_legend_frame, bg="#f0f9ff" if is_active else "#ffffff", cursor="hand2")
            row.pack(anchor="w", pady=1, fill="x")
            row.bind("<Button-1>", lambda e, s=label: self._filter_top_3_by_severity(s))

            lbl_sq = tk.Label(row, text="■", font=("Segoe UI", 9, "bold"), fg=color, bg="#f0f9ff" if is_active else "#ffffff", cursor="hand2")
            lbl_sq.pack(side="left")
            lbl_sq.bind("<Button-1>", lambda e, s=label: self._filter_top_3_by_severity(s))

            lbl_txt = tk.Label(
                row,
                text=f"{label}: {count} ({pct:.0f}%){' 👈' if is_active else ''}",
                font=("Segoe UI", 8, "bold" if (label=="CRITICAL" or is_active) else "normal"),
                fg="#0284c7" if is_active else "#0f172a",
                bg="#f0f9ff" if is_active else "#ffffff",
                cursor="hand2"
            )
            lbl_txt.pack(side="left", padx=2)
            lbl_txt.bind("<Button-1>", lambda e, s=label: self._filter_top_3_by_severity(s))
            ToolTip(row, f"Click to view Top 3 {label} priority issues.")

    def _filter_top_3_by_severity(self, severity: str):
        """Filters Top 3 Urgent Issues panel when clicking a pie chart slice or legend item."""
        if severity == "ALL" or self.active_pie_severity_filter == severity:
            self.active_pie_severity_filter = None
        else:
            self.active_pie_severity_filter = severity

        if self.scan_summary:
            sev_counts = self.scan_summary.get("severity_counts", {})
            findings = self.scan_summary.get("findings", [])
            self._draw_pie_chart(sev_counts)
            self._update_top_3_issues(findings, target_severity=self.active_pie_severity_filter)

    def _update_top_3_issues(self, findings: List[Dict[str, Any]], target_severity: Optional[str] = None):
        """Renders Top 3 Urgent Issues needing immediate remediation, optionally filtered by severity."""
        for w in self.top3_container.winfo_children():
            w.destroy()

        if target_severity is None:
            target_severity = self.active_pie_severity_filter

        if target_severity:
            self.lbl_top3_header.config(text=f"🔥 Top 3 Issues [{target_severity} Priority Filter]:", fg="#0284c7")
            self.btn_reset_pie_filter.pack(side="right")
        else:
            self.lbl_top3_header.config(text="🔥 Top 3 Priority Issues Requiring Remediation:", fg="#991b1b")
            self.btn_reset_pie_filter.pack_forget()

        if target_severity:
            filtered = [f for f in findings if f.get("severity") == target_severity]
        else:
            filtered = [f for f in findings if f.get("severity") != "PASS"]

        if not filtered:
            empty_box = tk.Frame(self.top3_container, bg="#f0fdf4", highlightthickness=1, highlightbackground="#bbf7d0", padx=10, pady=8)
            empty_box.pack(fill="x", pady=2)
            msg = f"No active {target_severity} findings detected." if target_severity else "Zero Active Violations Detected."
            tk.Label(empty_box, text=f"🎉 {msg}", font=("Segoe UI", 9, "bold"), fg="#166534", bg="#f0fdf4").pack(anchor="w")
            tk.Label(empty_box, text="All monitored files pass GRC security and encryption baselines.", font=("Segoe UI", 8), fg="#15803d", bg="#f0fdf4").pack(anchor="w")
            return

        sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "PASS": 0}
        sorted_issues = sorted(filtered, key=lambda x: (sev_rank.get(x.get("severity", "LOW"), 0), x.get("rule_id", "")), reverse=True)
        top_3 = sorted_issues[:3]

        remediation_hints = {
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": "🔒 Restrict Access: Lock file permissions so only owner can read/write (chmod 0640).",
            "ERR-OCTAL-WORLD-WRITABLE": "🔒 Restrict Access: Lock file permissions so only owner can read/write (chmod 0640).",
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": "🛡️ Encrypt Sensitive Data: Secure SSN / credit card records using AES-256 or GPG encryption.",
            "ERR-ENTROPY-PLAINTEXT-PII": "🛡️ Encrypt Sensitive Data: Secure unencrypted data records using AES-256 or GPG encryption.",
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": "⚙️ Harden Transmission: Disable weak SSH Protocol 1 & obsolete ciphers in sshd_config.",
            "INSECURE_SYSTEM_TLS_POLICY": "🌐 Upgrade Encryption: Require TLS 1.2 or TLS 1.3 minimum in system web/SSL policies.",
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": "🔑 Enforce Password Rotation: Update policy to require password change every 90 days (login.defs).",
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": "🚫 Disable Service Logins: Set system service account shells to /sbin/nologin.",
            "INSECURE_AUDIT_LOG_PERMISSIONS": "📋 Protect Audit Trails: Restrict /var/log/audit access exclusively to administrators (chmod 0600).",
            "UNENCRYPTED_RAW_ZLIB_STREAM": "🔐 Secure Archives: Encrypt compressed file streams with AES-256-CBC.",
            "DECOMPRESSION_SAFETY_BOMB_TEST": "⚠️ Inspect Compression: Check archive decompression ratio for safety boundary anomalies."
        }

        sev_colors = {
            "CRITICAL": ("#fee2e2", "#991b1b", "#ef4444"),
            "HIGH": ("#ffedd5", "#c2410c", "#f97316"),
            "MEDIUM": ("#fef9c3", "#a16207", "#eab308")
        }

        for idx, item in enumerate(top_3, 1):
            sev = item.get("severity", "MEDIUM")
            bg_color, fg_color, border_color = sev_colors.get(sev, ("#f1f5f9", "#334155", "#cbd5e1"))

            file_path = item.get("file_path", "N/A")
            rel_file = Path(file_path).name
            rule_id = item.get("rule_id", "N/A")
            
            advisory = item.get("rag_advisory", {})
            rem_cmd = advisory.get("remediation_command", remediation_hints.get(rule_id, "Remediate finding"))

            item_card = tk.Frame(self.top3_container, bg=bg_color, highlightthickness=1, highlightbackground=border_color, padx=8, pady=3)
            item_card.pack(fill="x", pady=2)

            top_row = tk.Frame(item_card, bg=bg_color)
            top_row.pack(fill="x")

            lbl_badge = tk.Label(top_row, text=f"#{idx} {sev}", font=("Segoe UI", 8, "bold"), fg="#ffffff", bg=border_color, padx=4, pady=1)
            lbl_badge.pack(side="left", padx=(0, 6))

            tk.Label(top_row, text=f"{rel_file}", font=("Segoe UI", 9, "bold"), fg=fg_color, bg=bg_color).pack(side="left")
            tk.Label(top_row, text=f"({rule_id})", font=("Segoe UI", 8), fg="#64748b", bg=bg_color).pack(side="left", padx=4)

            # Quick Action Button
            btn_fix = ttk.Button(
                top_row, text="📂 Reveal", style="Secondary.TButton",
                command=lambda f=file_path: reveal_in_file_explorer(Path(self.target_dir_var.get()) / f if not Path(f).is_absolute() else Path(f))
            )
            btn_fix.pack(side="right")
            ToolTip(btn_fix, f"Reveal {rel_file} in system Explorer/Finder.")

            # Remediation hint line
            bot_row = tk.Frame(item_card, bg=bg_color)
            bot_row.pack(fill="x", pady=(1, 0))
            tk.Label(bot_row, text=f"👉 Action: {rem_cmd[:60]}", font=("Consolas", 8), fg="#0f172a", bg=bg_color).pack(anchor="w")

    def _on_scan_error(self, err_msg: str):
        """Callback executed on GUI thread if scan errors out."""
        self.is_scanning = False
        self.is_monitoring = False
        self.btn_start.config(text="▶ START MONITORING", style="Primary.TButton")
        self.lbl_progress.config(text="Scan failed.")
        self.hero_status_lbl.config(text="🔴 Protection Error", fg="#b91c1c", bg="#fee2e2")
        messagebox.showerror("Scan Error", f"An error occurred during scan: {err_msg}")

    def _update_findings_table(self):
        """Populates running ledger table based on selected filter (Violations Only vs All)."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.displayed_findings.clear()
        if not self.scan_summary:
            return

        findings = self.scan_summary.get("findings", [])
        filter_mode = self.filter_var.get()

        domain_names = {
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": "🔑 Ref 01.02 / 01.c",
            "ERR-OCTAL-WORLD-WRITABLE": "🔑 Ref 01.02 / 01.c",
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": "🔑 Ref 01.02 / 01.c",
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": "🛡️ Ref 06.01 / 06.d",
            "ERR-ENTROPY-PLAINTEXT-PII": "🛡️ Ref 06.01 / 06.d",
            "ENCRYPTED_COMPLIANT_AES_256_CBC": "🛡️ Ref 06.01 / 06.d",
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": "⚙️ Ref 10.06 / 10.m",
            "INSECURE_SYSTEM_TLS_POLICY": "⚙️ Ref 10.06 / 10.m",
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": "⚙️ Ref 10.06 / 10.m",
            "DECOMPRESSION_SAFETY_BOMB_TEST": "⚙️ Ref 10.06 / 10.m",
            "UNENCRYPTED_RAW_ZLIB_STREAM": "📦 Ref 09.07 / 09.q",
            "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK": "📦 Ref 09.07 / 09.q",
            "INSECURE_AUDIT_LOG_PERMISSIONS": "📋 Ref 09.10 / 10.aa"
        }

        remediation_hints = {
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": "🔒 Restrict Access: Lock file permissions so only owner can read/write (chmod 0640).",
            "ERR-OCTAL-WORLD-WRITABLE": "🔒 Restrict Access: Lock file permissions so only owner can read/write (chmod 0640).",
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": "🛡️ Encrypt Sensitive Data: Secure SSN / credit card records using AES-256 or GPG encryption.",
            "ERR-ENTROPY-PLAINTEXT-PII": "🛡️ Encrypt Sensitive Data: Secure unencrypted data records using AES-256 or GPG encryption.",
            "ENCRYPTED_COMPLIANT_AES_256_CBC": "✅ Compliant: Verified AES-256-CBC payload encryption.",
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": "⚙️ Harden Transmission: Disable weak SSH Protocol 1 & obsolete ciphers in sshd_config.",
            "INSECURE_SYSTEM_TLS_POLICY": "🌐 Upgrade Encryption: Require TLS 1.2 or TLS 1.3 minimum in system web/SSL policies.",
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": "🔑 Enforce Password Rotation: Update policy to require password change every 90 days (login.defs).",
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": "🚫 Disable Service Logins: Set system service account shells to /sbin/nologin.",
            "INSECURE_AUDIT_LOG_PERMISSIONS": "📋 Protect Audit Trails: Restrict /var/log/audit access exclusively to administrators (chmod 0600).",
            "UNENCRYPTED_RAW_ZLIB_STREAM": "🔐 Secure Archives: Encrypt compressed file streams with AES-256-CBC.",
            "DECOMPRESSION_SAFETY_BOMB_TEST": "⚠️ Inspect Compression: Check archive decompression ratio for safety boundary anomalies."
        }

        for f in findings:
            severity = f.get("severity", "INFO")

            if filter_mode == "Violations Only" and severity == "PASS":
                continue

            self.displayed_findings.append(f)
            rule_id = f.get("rule_id", "N/A")
            title = f.get("title", "Finding")
            file_path = f.get("file_path", "N/A")
            domain = domain_names.get(rule_id, "⚙️ System Config")

            advisory = f.get("rag_advisory", {})
            rem_cmd = advisory.get("remediation_command", remediation_hints.get(rule_id, "Align file controls with GRC standard"))
            rem_clean = rem_cmd.replace("{filepath}", Path(file_path).name).replace("{file}", Path(file_path).name)

            self.tree.insert(
                "",
                "end",
                values=(severity, domain, file_path, title, rem_clean),
                tags=(severity,)
            )

    def _on_tree_select(self, event=None):
        """Populates expandable detail panel when user selects a finding row."""
        selected = self.tree.selection()
        if not selected:
            self.btn_reveal_file.config(state="disabled")
            return

        self.btn_reveal_file.config(state="normal")
        index = self.tree.index(selected[0])
        if index < 0 or index >= len(self.displayed_findings):
            return

        finding = self.displayed_findings[index]
        self._populate_detail_panel(finding)

    def _on_tree_double_click(self, event=None):
        """Pops out detailed inspection modal view when user double-clicks a finding row."""
        selected = self.tree.selection()
        if not selected:
            return
        index = self.tree.index(selected[0])
        if 0 <= index < len(self.displayed_findings):
            finding = self.displayed_findings[index]
            self._open_finding_detail_modal(finding)

    def _open_finding_detail_modal(self, f: Dict[str, Any]):
        """Pops out a rich detailed inspection modal window with interactive file hyperlink."""
        severity = f.get("severity", "INFO")
        title = f.get("title", "Security Finding")
        rule_id = f.get("rule_id", "N/A")
        rel_path = f.get("file_path", "N/A")
        desc = f.get("description", "No description available.")
        details = f.get("details", {})
        mappings = f.get("framework_mappings", [])
        advisory = f.get("rag_advisory", {})

        target_root = Path(self.target_dir_var.get()).resolve()
        full_path = (target_root / rel_path).resolve() if not Path(rel_path).is_absolute() else Path(rel_path).resolve()

        modal = tk.Toplevel(self.root)
        modal.title(f"Finding Inspection - {title}")
        modal.geometry("840x650")
        modal.minsize(700, 500)
        modal.configure(background="#f8fafc")
        modal.transient(self.root)
        modal.grab_set()

        # Modal Header Banner
        header = tk.Frame(modal, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=16, pady=12)
        header.pack(fill="x", padx=14, pady=(14, 10))

        sev_colors = {
            "CRITICAL": ("#fee2e2", "#991b1b", "🔴"),
            "HIGH": ("#ffedd5", "#c2410c", "🟠"),
            "MEDIUM": ("#fef9c3", "#a16207", "🟡"),
            "PASS": ("#dcfce7", "#15803d", "🟢")
        }
        bg_color, fg_color, icon = sev_colors.get(severity, ("#f1f5f9", "#334155", "ℹ️"))

        badge = tk.Label(header, text=f"{icon} {severity}", font=("Segoe UI", 10, "bold"), fg=fg_color, bg=bg_color, padx=8, pady=4)
        badge.pack(side="left", padx=(0, 10))

        h_text_box = tk.Frame(header, bg="#ffffff")
        h_text_box.pack(side="left", fill="both", expand=True)
        tk.Label(h_text_box, text=title, font=("Segoe UI", 12, "bold"), fg="#0f172a", bg="#ffffff", anchor="w").pack(fill="x")
        tk.Label(h_text_box, text=f"Rule ID: {rule_id}", font=("Consolas", 9), fg="#64748b", bg="#ffffff", anchor="w").pack(fill="x")

        # Clickable Hyperlink Card
        link_card = tk.Frame(modal, bg="#f0f9ff", highlightthickness=1, highlightbackground="#bae6fd", padx=14, pady=10)
        link_card.pack(fill="x", padx=14, pady=(0, 10))

        tk.Label(link_card, text="📁 Target File Location (Click link to follow path in Finder/Explorer):", font=("Segoe UI", 9, "bold"), fg="#0369a1", bg="#f0f9ff").pack(anchor="w")
        
        link_row = tk.Frame(link_card, bg="#f0f9ff")
        link_row.pack(fill="x", pady=(4, 0))

        # Styled Hyperlink Label
        file_url_text = full_path.as_uri() if full_path.exists() else str(full_path)
        lbl_link = tk.Label(
            link_row,
            text=file_url_text,
            font=("Consolas", 9, "underline"),
            fg="#0284c7",
            bg="#f0f9ff",
            cursor="hand2",
            anchor="w"
        )
        lbl_link.pack(side="left", fill="x", expand=True)
        ToolTip(lbl_link, f"Click to open '{full_path.name}' in native macOS Finder / Windows Explorer.")
        lbl_link.bind("<Button-1>", lambda e, p=full_path: reveal_in_file_explorer(p))

        btn_follow = ttk.Button(
            link_row,
            text="📂 Follow Path in Explorer",
            style="Primary.TButton",
            command=lambda p=full_path: reveal_in_file_explorer(p)
        )
        btn_follow.pack(side="right", padx=(8, 0))

        # Scrollable Detailed Content Text Area
        content_frame = tk.Frame(modal, bg="#ffffff", highlightthickness=1, highlightbackground="#e2e8f0", padx=12, pady=12)
        content_frame.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        scroll = ttk.Scrollbar(content_frame)
        scroll.pack(side="right", fill="y")

        txt = tk.Text(
            content_frame,
            wrap="word",
            font=("Consolas", 9),
            yscrollcommand=scroll.set,
            bg="#ffffff",
            fg="#0f172a",
            relief="flat",
            padx=8,
            pady=8
        )
        scroll.config(command=txt.yview)
        txt.pack(fill="both", expand=True)

        txt.tag_configure("SECTION", font=("Segoe UI", 10, "bold"), foreground="#0284c7")
        txt.tag_configure("LABEL", font=("Segoe UI", 9, "bold"), foreground="#475569")
        txt.tag_configure("VALUE", font=("Consolas", 9), foreground="#0f172a")
        txt.tag_configure("CMD", font=("Consolas", 9, "bold"), foreground="#0284c7", background="#f0f9ff")

        # Populate Text
        txt.insert("end", "📌 FINDING DESCRIPTION & AUDIT FINDINGS\n", "SECTION")
        txt.insert("end", f"{desc}\n\n", "VALUE")

        biz_explanation = details.get("business_explanation") or advisory.get("business_explanation", "")
        if biz_explanation:
            txt.insert("end", "🛡️ BUSINESS RISK & OPERATIONAL IMPACT\n", "SECTION")
            txt.insert("end", f"{biz_explanation}\n\n", "VALUE")

        if details:
            tech_details = {k: v for k, v in details.items() if k != "business_explanation"}
            if tech_details:
                txt.insert("end", "⚙️ TECHNICAL SCAN PARAMETERS\n", "SECTION")
                txt.insert("end", f"{json.dumps(tech_details, indent=2)}\n\n", "VALUE")

        if mappings:
            txt.insert("end", "📜 ADDRESSED GRC FRAMEWORK CITATIONS\n", "SECTION")
            for m in mappings:
                fw = m.get("framework", "GRC")
                cid = m.get("control_id", "N/A")
                ctitle = m.get("title", "Requirement")
                st = m.get("status", "REVIEW")
                txt.insert("end", f"  • [{fw}] {cid}: {ctitle} (Status: {st})\n", "VALUE")
            txt.insert("end", "\n")

        if advisory:
            txt.insert("end", "🤖 RAG AI REMEDIATION ADVISORY CARD\n", "SECTION")
            txt.insert("end", f"  • Mapped Clause ID     : {advisory.get('clause_id')}\n", "VALUE")
            txt.insert("end", f"  • Standards Involved   : {advisory.get('standard')}\n", "VALUE")
            txt.insert("end", f"  • Technical Risk       : {advisory.get('risk_statement')}\n", "VALUE")
            txt.insert("end", f"  • Recommended Command  : ", "LABEL")
            txt.insert("end", f"{advisory.get('remediation_command')}\n", "CMD")
            if advisory.get("rationale"):
                txt.insert("end", f"  • Context Rationale    : {advisory.get('rationale')}\n", "VALUE")

        txt.config(state="disabled")

        # Bottom Toolbar
        bottom = tk.Frame(modal, bg="#f8fafc", padx=14, pady=8)
        bottom.pack(fill="x")

        btn_close = ttk.Button(bottom, text="❌ Close Inspection", style="Secondary.TButton", command=modal.destroy)
        btn_close.pack(side="right")

    def _populate_detail_panel(self, f: Dict[str, Any]):
        """Renders rich formatted un-truncated finding details in lower card."""
        self.txt_detail.config(state="normal")
        self.txt_detail.delete("1.0", "end")

        severity = f.get("severity", "INFO")
        title = f.get("title", "Security Finding")
        rule_id = f.get("rule_id", "N/A")
        file_path = f.get("file_path", "N/A")
        desc = f.get("description", "No description available.")
        details = f.get("details", {})
        mappings = f.get("framework_mappings", [])

        self.txt_detail.insert("end", f"[{severity}] ", severity)
        self.txt_detail.insert("end", f"{title}\n", "TITLE")
        self.txt_detail.insert("end", f"{'─'*80}\n")

        self.txt_detail.insert("end", "• File Path              : ", "LABEL")
        self.txt_detail.insert("end", f"{file_path}\n", "VALUE")

        self.txt_detail.insert("end", "• Rule Identifier        : ", "LABEL")
        self.txt_detail.insert("end", f"{rule_id}\n", "VALUE")

        self.txt_detail.insert("end", "• Finding Description    : ", "LABEL")
        self.txt_detail.insert("end", f"{desc}\n", "VALUE")

        advisory = f.get("rag_advisory", {})
        biz_explanation = details.get("business_explanation") or advisory.get("business_explanation", "")

        if biz_explanation:
            self.txt_detail.insert("end", "• Business Risk & Meaning: ", "LABEL")
            self.txt_detail.insert("end", f"{biz_explanation}\n", "VALUE")

        if details:
            tech_details = {k: v for k, v in details.items() if k != "business_explanation"}
            if tech_details:
                self.txt_detail.insert("end", "• Technical Parameters   : ", "LABEL")
                self.txt_detail.insert("end", f"{json.dumps(tech_details)}\n", "VALUE")

        if mappings:
            self.txt_detail.insert("end", "\n• Addressed GRC Framework Controls:\n", "LABEL")
            for m in mappings:
                fw = m.get("framework", "GRC")
                cid = m.get("control_id", "N/A")
                ctitle = m.get("title", "Requirement")
                st = m.get("status", "REVIEW")
                self.txt_detail.insert("end", f"   - [{fw}] {cid}: {ctitle} ({st})\n", "TITLE")

        if advisory:
            self.txt_detail.insert("end", "\n• RAG AI Remediation Card:\n", "LABEL")
            self.txt_detail.insert("end", f"   - Mapped Clause ID     : {advisory.get('clause_id')}\n", "VALUE")
            self.txt_detail.insert("end", f"   - Standards Involved   : {advisory.get('standard')}\n", "VALUE")
            self.txt_detail.insert("end", f"   - Technical Risk       : {advisory.get('risk_statement')}\n", "VALUE")
            if advisory.get("business_explanation") and not details.get("business_explanation"):
                self.txt_detail.insert("end", f"   - Business Explanation : {advisory.get('business_explanation')}\n", "VALUE")
            self.txt_detail.insert("end", f"   - Recommended Command  : ", "LABEL")
            self.txt_detail.insert("end", f"{advisory.get('remediation_command')}\n", "CMD")
            if advisory.get("rationale"):
                self.txt_detail.insert("end", f"   - Context Rationale    : {advisory.get('rationale')}\n", "VALUE")

        self.txt_detail.config(state="disabled")

    def _browse_directory(self):
        """Browses system folders to select target directory to monitor."""
        folder = filedialog.askdirectory(title="Select Target Directory to Monitor")
        if folder:
            self.target_dir_var.set(folder)

    def _upload_custom_policy(self):
        """Allows the user to upload a reasonably sized JSON or text policy file into the policy ingester."""
        file_path = filedialog.askopenfilename(
            title="Upload Custom Company Policy Document",
            filetypes=[
                ("JSON Policy & Text Files", "*.json *.txt *.md"),
                ("JSON Files (*.json)", "*.json"),
                ("Text Files (*.txt)", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return

        path_obj = Path(file_path)

        # Enforce max 10MB size limit
        if path_obj.stat().st_size > 10 * 1024 * 1024:
            messagebox.showerror(
                "File Too Large",
                f"Selected policy file '{path_obj.name}' is {path_obj.stat().st_size / (1024*1024):.1f} MB.\n"
                "Please upload a reasonably sized policy file (under 10 MB)."
            )
            return

        self.custom_policy_var.set(file_path)

        if not self.rag_client:
            self.rag_client = RAGPipelineClient()
            self.rag_client.connect()

        self.lbl_policy_status.config(text="⏳ Vectorizing policy...", fg="#0284c7")
        self.root.update_idletasks()

        res = self.rag_client.ingest_and_vectorize_policy(path_obj)
        if res.get("status") in ["VECTORIZED", "SUCCESS"]:
            vector_cnt = res.get("vector_count", 0)
            self.lbl_policy_status.config(
                text=f"🟢 Policy Active: {path_obj.name} ({vector_cnt} rules vectorized)",
                fg="#15803d"
            )
            messagebox.showinfo(
                "Policy Vectorized Successfully",
                f"Custom policy '{path_obj.name}' successfully ingested!\n"
                f"• Rules/Chunks Vectorized: {vector_cnt}\n"
                f"• Storage: Vector FAISS index & SQLite compliance database."
            )
        else:
            err_msg = res.get("message", "Unknown error during policy ingestion.")
            self.lbl_policy_status.config(text=f"❌ Ingestion Failed: {err_msg}", fg="#dc2626")
            messagebox.showerror("Policy Ingestion Error", f"Failed to ingest custom policy:\n{err_msg}")

    def _export_pdf(self):
        """Triggers PDF export of current scan summary."""
        if not self.scan_summary:
            messagebox.showwarning("No Data", "Please run monitoring first before exporting PDF.")
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
    """Launches Windows Security style native Tkinter Desktop GUI application."""
    root = tk.Tk()
    app = KintsugiAppTkinterGUI(root)
    root.mainloop()
