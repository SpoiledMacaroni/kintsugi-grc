"""
Kintsugi-GRC Native Desktop GUI — PyQt6 Edition
Premium dark-mode compliance monitoring center with interactive file tree,
donut severity chart, sortable findings ledger, file detail viewer, and
real-time dynamic directory watcher integration.
"""

import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Suppress benign Qt font database script lookup notices
os.environ.setdefault("QT_LOGGING_RULES", "qt.text.font.db=false;qt.text.font.*=false")

from src.dep_check import ensure_dependencies
ensure_dependencies(["PyQt6", "PyQt6.QtCharts"])

from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve,
    QAbstractAnimation, QTimer, QSize, QPoint, QRect, QMargins,
)
from PyQt6.QtGui import (
    QColor, QFont, QFontDatabase, QPalette, QBrush, QPainter,
    QPen, QRadialGradient, QLinearGradient, QIcon, QPixmap,
    QTextCharFormat, QTextCursor, QAction,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QTabWidget, QLabel, QPushButton, QLineEdit, QComboBox, QProgressBar,
    QTextEdit, QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QScrollArea, QFrame, QHeaderView, QAbstractItemView, QSizePolicy,
    QStatusBar, QToolBar, QRadioButton, QButtonGroup, QGroupBox,
    QStyleOptionViewItem, QGridLayout, QSpacerItem,
)
from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries, QPieSlice,
)

from src.mapping.controls import ControlRegistry
from src.output.pdf_exporter import PDFComplianceExporter
from src.output.reporter import ScanReporter
from src.rag.pipeline import RAGPipelineClient
from src.scanner.audit import ScannerAuditLogger
from src.scanner.engine import ScannerEngine
from src.scanner.watcher import DynamicDirectoryWatcher

logger = logging.getLogger("kintsugi_ui")

# ──────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ──────────────────────────────────────────────────────────────────────────────
PALETTE = {
    "bg_base":        "#0d1117",
    "bg_surface":     "#161b22",
    "bg_elevated":    "#1c2128",
    "bg_card":        "#21262d",
    "border":         "#30363d",
    "border_active":  "#58a6ff",
    "text_primary":   "#e6edf3",
    "text_secondary": "#8b949e",
    "text_muted":     "#6e7681",
    "accent_blue":    "#58a6ff",
    "accent_cyan":    "#79c0ff",
    "green":          "#3fb950",
    "green_bg":       "#0f3a1f",
    "yellow":         "#d29922",
    "yellow_bg":      "#3a2a00",
    "orange":         "#db6d28",
    "orange_bg":      "#3a1a00",
    "red":            "#f85149",
    "red_bg":         "#3a0f0f",
    "sev_critical":   "#f85149",
    "sev_high":       "#db6d28",
    "sev_medium":     "#d29922",
    "sev_pass":       "#3fb950",
}

SEV_COLOR = {
    "CRITICAL": PALETTE["sev_critical"],
    "HIGH":     PALETTE["sev_high"],
    "MEDIUM":   PALETTE["sev_medium"],
    "PASS":     PALETTE["sev_pass"],
}

SEV_BG = {
    "CRITICAL": PALETTE["red_bg"],
    "HIGH":     PALETTE["orange_bg"],
    "MEDIUM":   PALETTE["yellow_bg"],
    "PASS":     PALETTE["green_bg"],
}

DOMAIN_NAMES = {
    "INSECURE_SYSTEM_ACCOUNT_HARDENING":         "⚙️ Ref 10.06 / 10.m",
    "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN":        "🛡️ Ref 06.01 / 06.d",
    "ERR-ENTROPY-PLAINTEXT-PII":                 "🛡️ Ref 06.01 / 06.d",
    "ENCRYPTED_COMPLIANT_AES_256_CBC":           "🛡️ Ref 06.01 / 06.d",
    "INSECURE_SSH_TRANSMISSION_PROTOCOL":        "⚙️ Ref 10.06 / 10.m",
    "INSECURE_SYSTEM_TLS_POLICY":                "⚙️ Ref 10.06 / 10.m",
    "INSECURE_PASSWORD_POLICY_MAX_DAYS":         "⚙️ Ref 10.06 / 10.m",
    "DECOMPRESSION_SAFETY_BOMB_TEST":            "⚙️ Ref 10.06 / 10.m",
    "UNENCRYPTED_RAW_ZLIB_STREAM":               "📦 Ref 09.07 / 09.q",
    "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK":       "📦 Ref 09.07 / 09.q",
    "INSECURE_AUDIT_LOG_PERMISSIONS":            "📋 Ref 09.10 / 10.aa",
    "COMPLIANT_SECURITY_BASELINE":               "✅ Baseline",
}

REMEDIATION_HINTS = {
    "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": "chmod 0640 <file>",
    "ERR-OCTAL-WORLD-WRITABLE":                 "chmod 0640 <file>",
    "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN":        "gpg --symmetric --cipher-algo AES256 <file>",
    "ERR-ENTROPY-PLAINTEXT-PII":                 "gpg --symmetric --cipher-algo AES256 <file>",
    "INSECURE_SSH_TRANSMISSION_PROTOCOL":        "Set Protocol 2 in /etc/ssh/sshd_config",
    "INSECURE_SYSTEM_TLS_POLICY":                "Set MinProtocol=TLSv1.2 in openssl.cnf",
    "INSECURE_PASSWORD_POLICY_MAX_DAYS":         "Set PASS_MAX_DAYS 90 in /etc/login.defs",
    "INSECURE_SYSTEM_ACCOUNT_HARDENING":         "usermod -s /sbin/nologin <daemon>",
    "INSECURE_AUDIT_LOG_PERMISSIONS":            "chmod 0600 /var/log/audit/audit.log",
    "UNENCRYPTED_RAW_ZLIB_STREAM":               "openssl enc -aes-256-cbc -in <file> -out <file>.enc",
    "DECOMPRESSION_SAFETY_BOMB_TEST":            "Inspect archive decompression ratio (>100:1)",
    "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK":       "Re-encrypt with AES-CBC or AES-GCM mode",
    "ENCRYPTED_COMPLIANT_AES_256_CBC":           "✅ Already encrypted — no action required.",
    "COMPLIANT_SECURITY_BASELINE":               "✅ Compliant — no action required.",
}


# ──────────────────────────────────────────────────────────────────────────────
# UTILITY
# ──────────────────────────────────────────────────────────────────────────────

def reveal_in_file_explorer(file_path: Path):
    """Reveals file in native system explorer (Finder / Explorer)."""
    abs_path = file_path.resolve()
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", str(abs_path)])
        elif sys.platform == "win32":
            subprocess.run(["explorer", "/select,", str(abs_path)])
        else:
            subprocess.run(["xdg-open", str(abs_path.parent)])
    except Exception as e:
        logger.error(f"Failed to open file in system explorer: {e}")


def apply_dark_palette(app: QApplication):
    """Applies system-wide dark QPalette."""
    palette = QPalette()
    bg   = QColor(PALETTE["bg_base"])
    surf = QColor(PALETTE["bg_surface"])
    txt  = QColor(PALETTE["text_primary"])
    dim  = QColor(PALETTE["text_secondary"])
    acc  = QColor(PALETTE["accent_blue"])
    palette.setColor(QPalette.ColorRole.Window,          bg)
    palette.setColor(QPalette.ColorRole.WindowText,      txt)
    palette.setColor(QPalette.ColorRole.Base,            surf)
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(PALETTE["bg_elevated"]))
    palette.setColor(QPalette.ColorRole.Text,            txt)
    palette.setColor(QPalette.ColorRole.BrightText,      QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Button,          QColor(PALETTE["bg_card"]))
    palette.setColor(QPalette.ColorRole.ButtonText,      txt)
    palette.setColor(QPalette.ColorRole.Highlight,       acc)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Link,            acc)
    palette.setColor(QPalette.ColorRole.PlaceholderText, dim)
    app.setPalette(palette)


# ──────────────────────────────────────────────────────────────────────────────
# BACKGROUND WORKER THREAD
# ──────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    """Runs the full scan + RAG advisory enrichment in a background thread."""
    progress     = pyqtSignal(int, str)
    scan_done    = pyqtSignal(dict)
    scan_error   = pyqtSignal(str)
    dynamic_done = pyqtSignal(dict, str)

    def __init__(self, target_dir: Path, industry: str, custom_policy: str = ""):
        super().__init__()
        self.target_dir    = target_dir
        self.industry      = industry
        self.custom_policy = custom_policy
        self.engine: Optional[ScannerEngine]          = None
        self.watcher: Optional[DynamicDirectoryWatcher] = None
        self.rag_client: Optional[RAGPipelineClient]  = None
        self._stop_flag = False

    def run(self):
        try:
            self.progress.emit(5,  "Initializing audit logger...")
            audit_log = self.target_dir / "kintsugi_scanner_audit.log"
            audit_logger = ScannerAuditLogger(audit_log)
            audit_logger.initialize()

            self.progress.emit(15, "Loading GRC control mappings...")
            control_reg = ControlRegistry()
            control_reg.load()

            self.progress.emit(25, f"Scanning target directory: {self.target_dir.name}...")
            self.engine = ScannerEngine(self.target_dir, control_reg, audit_logger, industry=self.industry)
            summary = self.engine.run_scan()

            self.progress.emit(60, "Connecting RAG pipeline...")
            self.rag_client = RAGPipelineClient()
            self.rag_client.connect()

            if self.custom_policy and Path(self.custom_policy).exists():
                self.progress.emit(65, "Vectorizing custom policy...")
                self.rag_client.ingest_and_vectorize_policy(Path(self.custom_policy))

            self.progress.emit(70, "Generating AI remediation advisories...")
            for f in summary.get("findings", []):
                if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                    advisory = self.rag_client.generate_advisory(f, industry=self.industry)
                    f["rag_advisory"] = advisory
                    f["rag_ai_remediation"] = advisory.get("remediation_command", "")

            audit_logger.finalize(summary["total_files_scanned"], summary["total_findings"])

            self.progress.emit(85, "Starting dynamic directory watcher...")
            self.watcher = DynamicDirectoryWatcher(
                target_dir=self.target_dir,
                on_file_changed=self._on_file_changed,
                on_file_deleted=self._on_file_deleted,
            )
            self.watcher.start()

            self.progress.emit(100, "Scan complete.")
            self.scan_done.emit(summary)

        except Exception as e:
            logger.error(f"ScanWorker error: {e}", exc_info=True)
            self.scan_error.emit(str(e))

    def _on_file_changed(self, path: Path, event: str):
        if not self.engine:
            return
        updated = self.engine.update_single_file(path, event)
        if self.rag_client:
            for f in updated.get("findings", []):
                if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"] and "rag_advisory" not in f:
                    advisory = self.rag_client.generate_advisory(f, industry=self.industry)
                    f["rag_advisory"] = advisory
                    f["rag_ai_remediation"] = advisory.get("remediation_command", "")
        score = updated.get("compliance_score", 0)
        remaining = [
            f for f in updated.get("findings", [])
            if path.name in f.get("file_path", "") and f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        msg = (
            f"✅ Remediated: {path.name} is now compliant! Score: {score}%"
            if not remaining
            else f"⚡ Re-scanned ({event}): {path.name} — Score: {score}%"
        )
        self.dynamic_done.emit(updated, msg)

    def _on_file_deleted(self, path: Path, event: str):
        if not self.engine:
            return
        updated = self.engine.update_single_file(path, event)
        score = updated.get("compliance_score", 0)
        self.dynamic_done.emit(updated, f"🗑️ Removed: {path.name} — Score: {score}%")

    def stop_watcher(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None


# ──────────────────────────────────────────────────────────────────────────────
# FINDING DETAIL MODAL
# ──────────────────────────────────────────────────────────────────────────────

class FindingDetailDialog(QDialog):
    """Rich modal showing full finding details with file hyperlink."""

    def __init__(self, finding: Dict[str, Any], target_root: Path, parent=None):
        super().__init__(parent)
        self.finding     = finding
        self.target_root = target_root
        self.setWindowTitle("Finding Inspection — Kintsugi-GRC")
        self.setMinimumSize(860, 620)
        self.setStyleSheet(self._dialog_css())
        self._build()

    # ------------------------------------------------------------------
    def _dialog_css(self) -> str:
        return f"""
        QDialog {{
            background: {PALETTE['bg_base']};
            color: {PALETTE['text_primary']};
            font-family: 'Segoe UI', 'Inter', sans-serif;
        }}
        QLabel {{ color: {PALETTE['text_primary']}; }}
        QPushButton {{
            background: {PALETTE['bg_card']};
            color: {PALETTE['text_primary']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            padding: 6px 14px;
            font-weight: bold;
        }}
        QPushButton:hover {{ background: {PALETTE['bg_elevated']}; border-color: {PALETTE['accent_blue']}; }}
        QPushButton#primary {{
            background: {PALETTE['accent_blue']};
            color: #000;
            border: none;
        }}
        QPushButton#primary:hover {{ background: {PALETTE['accent_cyan']}; }}
        QTextEdit {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            font-family: 'Consolas', 'JetBrains Mono', monospace;
            font-size: 12px;
        }}
        QFrame#headerCard {{
            background: {PALETTE['bg_card']};
            border: 1px solid {PALETTE['border']};
            border-radius: 8px;
        }}
        QFrame#linkCard {{
            background: {PALETTE['bg_surface']};
            border: 1px solid {PALETTE['border_active']};
            border-radius: 6px;
        }}
        """

    def _build(self):
        f          = self.finding
        severity   = f.get("severity", "INFO")
        title      = f.get("title", "Security Finding")
        rule_id    = f.get("rule_id", "N/A")
        rel_path   = f.get("file_path", "N/A")
        desc       = f.get("description", "No description.")
        details    = f.get("details", {})
        mappings   = f.get("framework_mappings", [])
        advisory   = f.get("rag_advisory", {})
        full_path  = (self.target_root / rel_path).resolve()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ── Header card ──────────────────────────────────────────────
        header = QFrame(objectName="headerCard")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(14, 12, 14, 12)

        sev_lbl = QLabel(f" {severity} ")
        sev_lbl.setStyleSheet(
            f"background:{SEV_COLOR.get(severity,'#8b949e')};"
            f"color:#000;font-weight:bold;font-size:11px;"
            f"border-radius:4px;padding:3px 8px;"
        )
        hl.addWidget(sev_lbl)

        txt_col = QVBoxLayout()
        t = QLabel(title)
        t.setStyleSheet(f"font-size:16px;font-weight:bold;color:{PALETTE['text_primary']};")
        r = QLabel(f"Rule ID: {rule_id}")
        r.setStyleSheet(f"font-size:11px;color:{PALETTE['text_muted']};font-family:monospace;")
        txt_col.addWidget(t)
        txt_col.addWidget(r)
        hl.addLayout(txt_col, 1)

        reveal_btn = QPushButton("📂  Reveal in Explorer")
        reveal_btn.setObjectName("primary")
        reveal_btn.clicked.connect(lambda: reveal_in_file_explorer(full_path))
        hl.addWidget(reveal_btn)
        layout.addWidget(header)

        # ── File path card ───────────────────────────────────────────
        link_card = QFrame(objectName="linkCard")
        ll = QHBoxLayout(link_card)
        ll.setContentsMargins(12, 8, 12, 8)
        path_lbl = QLabel(f"📁 <a style='color:{PALETTE['accent_blue']};' href='#'>{full_path}</a>")
        path_lbl.setStyleSheet("font-family:monospace;font-size:11px;")
        path_lbl.setWordWrap(True)
        path_lbl.linkActivated.connect(lambda: reveal_in_file_explorer(full_path))
        ll.addWidget(path_lbl)
        layout.addWidget(link_card)

        # ── Detail text ───────────────────────────────────────────────
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setAcceptRichText(True)
        html = self._build_html(desc, details, mappings, advisory)
        txt.setHtml(html)
        layout.addWidget(txt, 1)

        # ── Bottom bar ────────────────────────────────────────────────
        close_btn = QPushButton("✕  Close Inspection")
        close_btn.clicked.connect(self.accept)
        bb = QHBoxLayout()
        bb.addStretch()
        bb.addWidget(close_btn)
        layout.addLayout(bb)

    def _build_html(self, desc, details, mappings, advisory) -> str:
        bg   = PALETTE["bg_surface"]
        txt  = PALETTE["text_primary"]
        dim  = PALETTE["text_secondary"]
        acc  = PALETTE["accent_blue"]
        code = PALETTE["bg_elevated"]

        def section(icon, heading):
            return f"<p style='margin-top:12px;margin-bottom:4px;'><span style='color:{acc};font-weight:bold;font-size:13px;'>{icon} {heading}</span></p>"

        def row(label, value, mono=False):
            vf = f"<code style='background:{code};padding:1px 4px;border-radius:3px;color:{acc};'>{value}</code>" if mono else f"<span style='color:{txt};'>{value}</span>"
            return f"<p style='margin:2px 0;'><span style='color:{dim};font-weight:bold;'>{label}:</span> {vf}</p>"

        parts = [f"<div style='font-family:\"Segoe UI\",sans-serif;font-size:12px;color:{txt};'>"]

        parts.append(section("📌", "Finding Description"))
        parts.append(f"<p style='color:{txt};'>{desc}</p>")

        biz = details.get("business_explanation") or advisory.get("business_explanation", "")
        if biz:
            parts.append(section("🛡️", "Business Risk & Operational Impact"))
            parts.append(f"<p style='color:{txt};'>{biz}</p>")

        tech = {k: v for k, v in details.items() if k != "business_explanation"}
        if tech:
            parts.append(section("⚙️", "Technical Scan Parameters"))
            parts.append(
                f"<pre style='background:{code};border-radius:6px;padding:8px 12px;"
                f"color:{acc};font-size:11px;white-space:pre-wrap;'>{json.dumps(tech, indent=2)}</pre>"
            )

        if mappings:
            parts.append(section("📜", "Addressed GRC Framework Citations"))
            for m in mappings:
                fw    = m.get("framework", "GRC")
                cid   = m.get("control_id", "N/A")
                ctit  = m.get("title", "Requirement")
                st    = m.get("status", "REVIEW")
                parts.append(f"<p style='margin:2px 0;'>• <span style='color:{acc};font-weight:bold;'>[{fw}] {cid}</span>: {ctit} <span style='color:{dim};'>({st})</span></p>")

        if advisory:
            parts.append(section("🤖", "RAG AI Remediation Advisory"))
            parts.append(row("Mapped Clause ID",    advisory.get("clause_id", "—")))
            parts.append(row("Standards Involved",  advisory.get("standard",  "—")))
            parts.append(row("Technical Risk",      advisory.get("risk_statement", "—")))
            cmd = advisory.get("remediation_command", "")
            if cmd:
                parts.append(f"<p style='margin:4px 0;'><span style='color:{dim};font-weight:bold;'>Recommended Command:</span><br><code style='background:{code};border-radius:4px;padding:4px 8px;color:{acc};font-size:11px;'>{cmd}</code></p>")
            if advisory.get("rationale"):
                parts.append(row("Context Rationale", advisory.get("rationale", "")))

        parts.append("</div>")
        return "".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# SEVERITY DONUT CHART WIDGET
# ──────────────────────────────────────────────────────────────────────────────

class SeverityDonutChart(QChartView):
    """Qt Charts donut chart — clickable slices filter the findings table."""
    slice_clicked = pyqtSignal(str)   # emits severity string or "ALL"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setMinimumSize(QSize(220, 200))
        self._active_filter: Optional[str] = None
        self._build_empty()

    def _build_empty(self):
        chart = QChart()
        chart.setBackgroundBrush(QBrush(QColor(PALETTE["bg_card"])))
        chart.setBackgroundRoundness(8)
        chart.legend().setVisible(False)
        chart.setMargins(QMargins(2, 2, 2, 2))
        ph = QLabel("Run scan\nto view chart", alignment=Qt.AlignmentFlag.AlignCenter)
        self.setChart(chart)

    def update_data(self, sev_counts: Dict[str, int], active_filter: Optional[str] = None):
        self._active_filter = active_filter
        total = sum(sev_counts.values())
        if total == 0:
            self._build_empty()
            return

        series = QPieSeries()
        series.setHoleSize(0.52)
        series.setPieSize(0.85)

        order = [("CRITICAL", PALETTE["sev_critical"]),
                 ("HIGH",     PALETTE["sev_high"]),
                 ("MEDIUM",   PALETTE["sev_medium"]),
                 ("PASS",     PALETTE["sev_pass"])]

        for sev, color in order:
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            sl = QPieSlice(f"{sev}\n{count}", count)
            sl.setColor(QColor(color))
            sl.setBorderColor(QColor(PALETTE["bg_card"]))
            sl.setBorderWidth(2)
            if active_filter == sev:
                sl.setExploded(True)
                sl.setExplodeDistanceFactor(0.08)
            sl.clicked.connect(lambda checked=False, s=sev: self._on_slice_clicked(s))
            series.append(sl)

        chart = QChart()
        chart.addSeries(series)
        chart.setBackgroundBrush(QBrush(QColor(PALETTE["bg_card"])))
        chart.setBackgroundRoundness(8)
        chart.legend().setVisible(False)
        chart.setMargins(QMargins(4, 4, 4, 4))
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        self.setChart(chart)

    def _on_slice_clicked(self, severity: str):
        if self._active_filter == severity:
            self.slice_clicked.emit("ALL")
        else:
            self.slice_clicked.emit(severity)


# ──────────────────────────────────────────────────────────────────────────────
# LEGEND WIDGET FOR DONUT
# ──────────────────────────────────────────────────────────────────────────────

class SeverityLegend(QWidget):
    filter_clicked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._active: Optional[str] = None

    def update_data(self, sev_counts: Dict[str, int], active: Optional[str] = None):
        self._active = active
        for i in reversed(range(self._layout.count())):
            w = self._layout.itemAt(i).widget()
            if w:
                w.deleteLater()

        total = sum(sev_counts.values())
        if total == 0:
            lbl = QLabel("No scan data")
            lbl.setStyleSheet(f"color:{PALETTE['text_muted']};font-style:italic;font-size:11px;")
            self._layout.addWidget(lbl)
            return

        order = [("CRITICAL", PALETTE["sev_critical"]),
                 ("HIGH",     PALETTE["sev_high"]),
                 ("MEDIUM",   PALETTE["sev_medium"]),
                 ("PASS",     PALETTE["sev_pass"])]

        for sev, color in order:
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            pct = (count / total) * 100
            is_active = (active == sev)

            row_w = QWidget()
            row_w.setCursor(Qt.CursorShape.PointingHandCursor)
            bg = f"background:{PALETTE['bg_elevated']};border-radius:4px;" if is_active else ""
            row_w.setStyleSheet(f"QWidget {{ {bg} }}")

            rl = QHBoxLayout(row_w)
            rl.setContentsMargins(4, 2, 4, 2)

            dot = QLabel("●")
            dot.setStyleSheet(f"color:{color};font-size:14px;")
            rl.addWidget(dot)

            lbl = QLabel(f"{sev}: {count}  ({pct:.0f}%)" + (" ◀" if is_active else ""))
            lbl.setStyleSheet(
                f"color:{PALETTE['accent_blue'] if is_active else PALETTE['text_primary']};"
                f"font-size:11px;font-weight:{'bold' if is_active else 'normal'};"
            )
            rl.addWidget(lbl, 1)

            row_w.mousePressEvent = (lambda e, s=sev: self.filter_clicked.emit(s))
            self._layout.addWidget(row_w)


# ──────────────────────────────────────────────────────────────────────────────
# TOP-3 ISSUES WIDGET
# ──────────────────────────────────────────────────────────────────────────────

class Top3Widget(QWidget):
    reveal_requested = pyqtSignal(str)   # rel_path

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(6)

    def update_issues(self, findings: List[Dict], severity_filter: Optional[str] = None):
        for i in reversed(range(self._layout.count())):
            w = self._layout.itemAt(i).widget()
            if w:
                w.deleteLater()

        if severity_filter:
            candidates = [f for f in findings if f.get("severity") == severity_filter]
        else:
            candidates = [f for f in findings if f.get("severity") != "PASS"]

        if not candidates:
            lbl = QLabel("🎉  Zero active violations — all files compliant!")
            lbl.setStyleSheet(
                f"color:{PALETTE['green']};font-weight:bold;font-size:12px;"
                f"background:{PALETTE['green_bg']};border-radius:6px;padding:8px;"
            )
            lbl.setWordWrap(True)
            self._layout.addWidget(lbl)
            return

        sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        top3 = sorted(candidates, key=lambda x: (sev_rank.get(x.get("severity", ""), 0)), reverse=True)[:3]

        for idx, item in enumerate(top3, 1):
            sev     = item.get("severity", "MEDIUM")
            color   = SEV_COLOR.get(sev, PALETTE["text_secondary"])
            bgc     = SEV_BG.get(sev,   PALETTE["bg_elevated"])
            rule_id = item.get("rule_id", "")
            fname   = Path(item.get("file_path", "N/A")).name
            rem_cmd = REMEDIATION_HINTS.get(rule_id, "Review finding")

            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background:{bgc};border:1px solid {color}40;"
                f"border-radius:6px;padding:2px; }}"
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(10, 6, 10, 6)
            cl.setSpacing(2)

            top_row = QHBoxLayout()
            badge = QLabel(f" #{idx} {sev} ")
            badge.setStyleSheet(
                f"background:{color};color:#000;font-weight:bold;"
                f"font-size:10px;border-radius:3px;padding:2px 6px;"
            )
            top_row.addWidget(badge)
            file_lbl = QLabel(fname)
            file_lbl.setStyleSheet(f"color:{color};font-weight:bold;font-size:12px;")
            top_row.addWidget(file_lbl, 1)

            reveal_btn = QPushButton("📂")
            reveal_btn.setFixedSize(QSize(28, 24))
            reveal_btn.setStyleSheet(
                f"QPushButton{{background:{PALETTE['bg_card']};color:{PALETTE['text_primary']};"
                f"border:1px solid {PALETTE['border']};border-radius:4px;font-size:11px;}}"
                f"QPushButton:hover{{background:{PALETTE['bg_elevated']};}}"
            )
            rel_path = item.get("file_path", "")
            reveal_btn.clicked.connect(lambda _, p=rel_path: self.reveal_requested.emit(p))
            top_row.addWidget(reveal_btn)
            cl.addLayout(top_row)

            action_lbl = QLabel(f"👉  {rem_cmd[:80]}")
            action_lbl.setStyleSheet(
                f"color:{PALETTE['text_secondary']};font-family:monospace;font-size:10px;"
            )
            action_lbl.setWordWrap(True)
            cl.addWidget(action_lbl)
            self._layout.addWidget(card)


# ──────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION WINDOW
# ──────────────────────────────────────────────────────────────────────────────

class KintsugiGRCApp(QMainWindow):
    """Premium dark-mode PyQt6 Compliance Monitoring Center."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kintsugi GRC — Security & Compliance Monitoring Center")
        self.setMinimumSize(1280, 820)
        self.resize(1440, 900)

        self.scan_summary: Optional[Dict[str, Any]] = None
        self.displayed_findings: List[Dict[str, Any]] = []
        self._filter_severity: Optional[str]          = None
        self._filter_text: str                         = ""
        self._filter_mode: str                         = "Violations Only"
        self._is_monitoring: bool                      = False
        self._worker: Optional[ScanWorker]             = None
        self._selected_finding: Optional[Dict]         = None

        self._apply_stylesheet()
        self._build_ui()

    # ── Stylesheet ─────────────────────────────────────────────────────────────
    def _apply_stylesheet(self):
        self.setStyleSheet(f"""
        QMainWindow, QWidget {{
            background: {PALETTE['bg_base']};
            color: {PALETTE['text_primary']};
            font-family: 'Segoe UI', 'Inter', 'SF Pro Display', sans-serif;
            font-size: 13px;
        }}
        QSplitter::handle {{
            background: {PALETTE['border']};
            width: 1px;
        }}
        QLabel {{ color: {PALETTE['text_primary']}; }}
        QLineEdit {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 12px;
        }}
        QLineEdit:focus {{ border-color: {PALETTE['accent_blue']}; }}
        QComboBox {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            padding: 5px 10px;
            font-size: 12px;
        }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox QAbstractItemView {{
            background: {PALETTE['bg_card']};
            color: {PALETTE['text_primary']};
            selection-background-color: {PALETTE['accent_blue']};
        }}
        QPushButton {{
            background: {PALETTE['bg_card']};
            color: {PALETTE['text_primary']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            padding: 6px 16px;
            font-weight: 600;
            font-size: 12px;
        }}
        QPushButton:hover {{
            background: {PALETTE['bg_elevated']};
            border-color: {PALETTE['accent_blue']};
        }}
        QPushButton:pressed {{ background: {PALETTE['bg_surface']}; }}
        QPushButton#btnPrimary {{
            background: {PALETTE['accent_blue']};
            color: #0d1117;
            border: none;
        }}
        QPushButton#btnPrimary:hover {{ background: {PALETTE['accent_cyan']}; }}
        QPushButton#btnDanger {{
            background: {PALETTE['red']};
            color: #fff;
            border: none;
        }}
        QPushButton#btnDanger:hover {{ background: #ff6b6b; }}
        QPushButton:disabled {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_muted']};
            border-color: {PALETTE['border']};
        }}
        QProgressBar {{
            background: {PALETTE['bg_surface']};
            border: 1px solid {PALETTE['border']};
            border-radius: 4px;
            height: 8px;
            text-align: center;
            color: transparent;
        }}
        QProgressBar::chunk {{
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {PALETTE['accent_blue']}, stop:1 {PALETTE['green']});
            border-radius: 4px;
        }}
        QTableWidget {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            gridline-color: {PALETTE['border']};
            border: 1px solid {PALETTE['border']};
            border-radius: 6px;
            selection-background-color: {PALETTE['bg_elevated']};
            alternate-background-color: {PALETTE['bg_card']};
        }}
        QHeaderView::section {{
            background: {PALETTE['bg_card']};
            color: {PALETTE['text_secondary']};
            border: none;
            border-bottom: 1px solid {PALETTE['border']};
            padding: 6px 8px;
            font-weight: bold;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        QTableWidget::item {{ padding: 4px 8px; }}
        QTableWidget::item:selected {{
            background: {PALETTE['bg_elevated']};
            color: {PALETTE['text_primary']};
        }}
        QTreeWidget {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            border: none;
            border-radius: 0;
            font-size: 12px;
        }}
        QTreeWidget::item {{ padding: 3px 4px; }}
        QTreeWidget::item:selected {{
            background: {PALETTE['bg_elevated']};
            color: {PALETTE['accent_blue']};
        }}
        QTreeWidget::item:hover {{ background: {PALETTE['bg_card']}; }}
        QScrollBar:vertical {{
            background: {PALETTE['bg_surface']};
            width: 8px;
            border-radius: 4px;
        }}
        QScrollBar::handle:vertical {{
            background: {PALETTE['border']};
            border-radius: 4px;
            min-height: 20px;
        }}
        QScrollBar::handle:vertical:hover {{ background: {PALETTE['text_muted']}; }}
        QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
        QTabWidget::pane {{
            border: 1px solid {PALETTE['border']};
            border-radius: 0 6px 6px 6px;
            background: {PALETTE['bg_surface']};
        }}
        QTabBar::tab {{
            background: {PALETTE['bg_card']};
            color: {PALETTE['text_secondary']};
            border: 1px solid {PALETTE['border']};
            border-bottom: none;
            border-radius: 6px 6px 0 0;
            padding: 7px 18px;
            font-weight: bold;
            font-size: 12px;
        }}
        QTabBar::tab:selected {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['accent_blue']};
            border-color: {PALETTE['accent_blue']};
        }}
        QTabBar::tab:hover {{ color: {PALETTE['text_primary']}; }}
        QTextEdit {{
            background: {PALETTE['bg_surface']};
            color: {PALETTE['text_primary']};
            border: none;
            font-family: 'Consolas', 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 12px;
        }}
        QRadioButton {{ color: {PALETTE['text_primary']}; }}
        QRadioButton::indicator {{
            width: 14px; height: 14px;
            border-radius: 7px;
            border: 2px solid {PALETTE['border']};
            background: {PALETTE['bg_surface']};
        }}
        QRadioButton::indicator:checked {{
            background: {PALETTE['accent_blue']};
            border-color: {PALETTE['accent_blue']};
        }}
        """)

    # ── Build UI ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        root_layout.addWidget(self._build_header())
        root_layout.addWidget(self._build_config_bar())
        root_layout.addWidget(self._build_progress_bar_row())

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        splitter.addWidget(self._build_file_tree_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([280, 1100])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        root_layout.addWidget(splitter, 1)

        root_layout.addWidget(self._build_status_bar())

    # ── Header ─────────────────────────────────────────────────────────────────
    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setFixedHeight(70)
        header.setStyleSheet(
            f"QFrame {{ background: {PALETTE['bg_surface']};"
            f"border-bottom: 1px solid {PALETTE['border']}; }}"
        )
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 20, 0)

        # Shield + title
        shield = QLabel("🛡️")
        shield.setStyleSheet("font-size: 28px;")
        hl.addWidget(shield)

        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        t1 = QLabel("Security & Compliance Protection Center")
        t1.setStyleSheet(f"font-size:18px;font-weight:bold;color:{PALETTE['text_primary']};")
        t2 = QLabel("Dynamic File Watcher · Automated GRC Control Audit (HIPAA · PCI DSS · NIST)")
        t2.setStyleSheet(f"font-size:11px;color:{PALETTE['text_secondary']};")
        title_col.addWidget(t1)
        title_col.addWidget(t2)
        hl.addLayout(title_col, 1)

        # Health score ring label
        self._score_lbl = QLabel("—%")
        self._score_lbl.setStyleSheet(
            f"font-size:28px;font-weight:bold;color:{PALETTE['accent_blue']};"
        )
        self._score_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_sub = QLabel("Health Score")
        score_sub.setStyleSheet(f"font-size:10px;color:{PALETTE['text_muted']};")
        score_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sc = QVBoxLayout()
        sc.setSpacing(0)
        sc.addWidget(self._score_lbl)
        sc.addWidget(score_sub)
        hl.addLayout(sc)

        hl.addSpacing(20)

        # Status badge
        self._status_badge = QLabel("  🟢  Ready  ")
        self._status_badge.setStyleSheet(
            f"background:{PALETTE['green_bg']};color:{PALETTE['green']};"
            f"font-weight:bold;font-size:12px;border-radius:16px;padding:6px 14px;"
        )
        hl.addWidget(self._status_badge)

        hl.addSpacing(16)

        # PDF button
        self._btn_pdf = QPushButton("📄  Export PDF")
        self._btn_pdf.setEnabled(False)
        self._btn_pdf.clicked.connect(self._export_pdf)
        hl.addWidget(self._btn_pdf)

        return header

    # ── Config bar ─────────────────────────────────────────────────────────────
    def _build_config_bar(self) -> QWidget:
        bar = QFrame()
        bar.setStyleSheet(
            f"QFrame {{ background:{PALETTE['bg_card']};"
            f"border-bottom:1px solid {PALETTE['border']}; }}"
        )
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(16, 8, 16, 8)
        hl.setSpacing(10)

        # Target dir
        target_lbl = QLabel("Target Directory:")
        target_lbl.setStyleSheet(f"color:{PALETTE['text_secondary']};font-weight:bold;font-size:11px;")
        hl.addWidget(target_lbl)

        self._target_edit = QLineEdit()
        self._target_edit.setText(os.path.abspath("./synthetic_test_env"))
        self._target_edit.setPlaceholderText("/path/to/scan...")
        hl.addWidget(self._target_edit, 2)

        btn_browse = QPushButton("Browse...")
        btn_browse.setMinimumWidth(100)
        btn_browse.setToolTip("Browse for target directory")
        btn_browse.clicked.connect(self._browse_target)
        hl.addWidget(btn_browse)

        btn_open = QPushButton("Open Folder")
        btn_open.setMinimumWidth(110)
        btn_open.setToolTip("Open target folder in Finder/Explorer")
        btn_open.clicked.connect(self._open_target_in_explorer)
        hl.addWidget(btn_open)

        hl.addSpacing(12)

        # Policy
        policy_lbl = QLabel("Policy:")
        policy_lbl.setStyleSheet(f"color:{PALETTE['text_secondary']};font-weight:bold;font-size:11px;")
        hl.addWidget(policy_lbl)

        self._policy_edit = QLineEdit()
        self._policy_edit.setPlaceholderText("Custom policy.json (optional)")
        self._policy_edit.setMaximumWidth(220)
        hl.addWidget(self._policy_edit)

        btn_policy = QPushButton("Upload Policy")
        btn_policy.setMinimumWidth(130)
        btn_policy.setToolTip("Upload custom JSON/text policy file")
        btn_policy.clicked.connect(self._upload_policy)
        hl.addWidget(btn_policy)

        hl.addSpacing(12)

        # Industry
        ind_lbl = QLabel("Industry:")
        ind_lbl.setStyleSheet(f"color:{PALETTE['text_secondary']};font-weight:bold;font-size:11px;")
        hl.addWidget(ind_lbl)

        self._industry_cb = QComboBox()
        self._industry_cb.addItems([
            "All Industries", "Healthcare",
            "Merchant / E-Commerce", "Finance / Treasury", "Banking / SWIFT",
        ])
        self._industry_cb.setMinimumWidth(160)
        hl.addWidget(self._industry_cb)

        hl.addStretch()

        # Start / Stop button
        self._btn_monitor = QPushButton("▶  Start Monitoring")
        self._btn_monitor.setObjectName("btnPrimary")
        self._btn_monitor.setMinimumWidth(160)
        self._btn_monitor.clicked.connect(self._toggle_monitoring)
        hl.addWidget(self._btn_monitor)

        return bar

    # ── Progress bar row ────────────────────────────────────────────────────────
    def _build_progress_bar_row(self) -> QWidget:
        frame = QFrame()
        frame.setFixedHeight(36)
        frame.setStyleSheet(f"background:{PALETTE['bg_base']};border-bottom:1px solid {PALETTE['border']};")
        hl = QHBoxLayout(frame)
        hl.setContentsMargins(16, 4, 16, 4)
        hl.setSpacing(12)

        self._progress_lbl = QLabel("Ready — select a target directory and click Start Monitoring.")
        self._progress_lbl.setStyleSheet(f"font-size:11px;color:{PALETTE['text_secondary']};font-style:italic;")
        hl.addWidget(self._progress_lbl, 1)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFixedWidth(200)
        self._progress_bar.setTextVisible(False)
        hl.addWidget(self._progress_bar)

        return frame

    # ── File tree (left panel) ─────────────────────────────────────────────────
    def _build_file_tree_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(220)
        panel.setMaximumWidth(380)
        vl = QVBoxLayout(panel)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        # Panel header
        hdr = QFrame()
        hdr.setFixedHeight(36)
        hdr.setStyleSheet(
            f"background:{PALETTE['bg_card']};border-right:1px solid {PALETTE['border']};"
            f"border-bottom:1px solid {PALETTE['border']};"
        )
        hhl = QHBoxLayout(hdr)
        hhl.setContentsMargins(12, 0, 8, 0)
        hl = QLabel("📁  File Tree")
        hl.setStyleSheet(f"font-weight:bold;font-size:12px;color:{PALETTE['text_secondary']};")
        hhl.addWidget(hl)
        hhl.addStretch()

        collapse_btn = QPushButton("⊟")
        collapse_btn.setFixedSize(QSize(24, 20))
        collapse_btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:{PALETTE['text_muted']};"
            f"border:none;font-size:14px;}}"
            f"QPushButton:hover{{color:{PALETTE['text_primary']};}}"
        )
        collapse_btn.setToolTip("Collapse all tree nodes")
        collapse_btn.clicked.connect(lambda: self._file_tree.collapseAll())
        hhl.addWidget(collapse_btn)
        vl.addWidget(hdr)

        # Filter search inside tree
        self._tree_search = QLineEdit()
        self._tree_search.setPlaceholderText("🔍 Filter files...")
        self._tree_search.setStyleSheet(
            f"background:{PALETTE['bg_surface']};border:none;"
            f"border-bottom:1px solid {PALETTE['border']};"
            f"border-radius:0;padding:6px 12px;font-size:11px;"
        )
        self._tree_search.textChanged.connect(self._filter_file_tree)
        vl.addWidget(self._tree_search)

        # Tree widget
        self._file_tree = QTreeWidget()
        self._file_tree.setHeaderHidden(True)
        self._file_tree.setAnimated(True)
        self._file_tree.setStyleSheet(
            f"QTreeWidget {{ border-right:1px solid {PALETTE['border']}; }}"
        )
        self._file_tree.itemClicked.connect(self._on_tree_item_clicked)
        vl.addWidget(self._file_tree, 1)

        # Legend
        legend_frame = QFrame()
        legend_frame.setStyleSheet(
            f"background:{PALETTE['bg_card']};border-top:1px solid {PALETTE['border']};"
            f"border-right:1px solid {PALETTE['border']};"
        )
        lfl = QVBoxLayout(legend_frame)
        lfl.setContentsMargins(10, 6, 10, 6)
        lfl.setSpacing(2)
        leg_title = QLabel("SEVERITY LEGEND")
        leg_title.setStyleSheet(f"font-size:9px;color:{PALETTE['text_muted']};font-weight:bold;letter-spacing:1px;")
        lfl.addWidget(leg_title)
        for sev, color in [("CRITICAL", PALETTE["sev_critical"]), ("HIGH", PALETTE["sev_high"]),
                            ("MEDIUM", PALETTE["sev_medium"]), ("PASS", PALETTE["sev_pass"])]:
            r = QLabel(f"● {sev}")
            r.setStyleSheet(f"color:{color};font-size:10px;")
            lfl.addWidget(r)
        vl.addWidget(legend_frame)

        return panel

    # ── Right panel (tabs) ─────────────────────────────────────────────────────
    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        vl = QVBoxLayout(panel)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_dashboard_tab(), "  📊  Dashboard  ")
        self._tabs.addTab(self._build_file_detail_tab(), "  🔍  File Detail  ")
        vl.addWidget(self._tabs, 1)

        return panel

    # -- Dashboard tab -------------------------------------------------------
    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        self._dash_vl = QVBoxLayout(w)
        self._dash_vl.setContentsMargins(12, 12, 12, 12)
        self._dash_vl.setSpacing(8)

        # --- Executive summary card -----------------------------------------
        self._exec_card = QFrame()
        self._exec_card.setStyleSheet(
            f"QFrame{{ background:{PALETTE['bg_card']};border:1px solid {PALETTE['border']};"
            f"border-radius:8px; }}"
        )
        # no height cap -- let the layout split determine size
        exec_outer = QVBoxLayout(self._exec_card)
        exec_outer.setContentsMargins(0, 0, 0, 0)
        exec_outer.setSpacing(0)

        exec_hdr = QFrame()
        exec_hdr.setFixedHeight(30)
        exec_hdr.setStyleSheet(
            f"background:{PALETTE['bg_elevated']};border-bottom:1px solid {PALETTE['border']};"
            f"border-radius:8px 8px 0 0;"
        )
        exec_hdr_l = QHBoxLayout(exec_hdr)
        exec_hdr_l.setContentsMargins(12, 0, 8, 0)
        exec_ttl = QLabel("Executive Summary")
        exec_ttl.setStyleSheet(
            f"font-size:11px;font-weight:bold;color:{PALETTE['text_secondary']};"
        )
        exec_hdr_l.addWidget(exec_ttl, 1)
        self._btn_expand_exec = QPushButton("[+]")
        self._btn_expand_exec.setFixedSize(QSize(32, 20))
        self._btn_expand_exec.setToolTip("Expand / restore this section")
        self._btn_expand_exec.setStyleSheet(
            f"QPushButton{{background:transparent;color:{PALETTE['text_muted']};"
            f"border:none;font-size:11px;font-weight:bold;}}"
            f"QPushButton:hover{{color:{PALETTE['accent_blue']};}}"
        )
        self._btn_expand_exec.clicked.connect(self._toggle_exec_expand)
        exec_hdr_l.addWidget(self._btn_expand_exec)
        exec_outer.addWidget(exec_hdr)

        exec_content = QHBoxLayout()
        exec_content.setContentsMargins(10, 4, 10, 6)
        exec_content.setSpacing(10)

        chart_inner = QFrame()
        chart_inner.setStyleSheet("QFrame{background:transparent;}")
        ccl = QHBoxLayout(chart_inner)
        ccl.setContentsMargins(0, 0, 0, 0)
        ccl.setSpacing(8)
        self._donut = SeverityDonutChart()
        self._donut.setMinimumSize(QSize(150, 140))
        self._donut.setMaximumSize(QSize(190, 175))
        self._donut.slice_clicked.connect(self._on_severity_filter)
        ccl.addWidget(self._donut)
        self._legend = SeverityLegend()
        self._legend.filter_clicked.connect(self._on_severity_filter)
        ccl.addWidget(self._legend)
        exec_content.addWidget(chart_inner, 1)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.VLine)
        div.setStyleSheet(f"color:{PALETTE['border']};")
        exec_content.addWidget(div)

        top3_inner = QFrame()
        top3_inner.setStyleSheet("QFrame{background:transparent;}")
        t3cl = QVBoxLayout(top3_inner)
        t3cl.setContentsMargins(4, 0, 0, 0)
        t3cl.setSpacing(4)
        t3_hdr = QHBoxLayout()
        t3_title = QLabel("Top 3 Priority Issues")
        t3_title.setStyleSheet(f"font-size:12px;font-weight:bold;color:{PALETTE['red']};")
        t3_hdr.addWidget(t3_title, 1)
        self._btn_reset_filter = QPushButton("Reset")
        self._btn_reset_filter.setFixedHeight(20)
        self._btn_reset_filter.setStyleSheet(
            f"QPushButton{{background:{PALETTE['bg_elevated']};color:{PALETTE['accent_blue']};"
            f"border:1px solid {PALETTE['border']};border-radius:4px;padding:0 6px;font-size:10px;}}"
            f"QPushButton:hover{{border-color:{PALETTE['accent_blue']};}}"
        )
        self._btn_reset_filter.setVisible(False)
        self._btn_reset_filter.clicked.connect(lambda: self._on_severity_filter("ALL"))
        t3_hdr.addWidget(self._btn_reset_filter)
        t3cl.addLayout(t3_hdr)
        self._top3 = Top3Widget()
        self._top3.reveal_requested.connect(self._reveal_by_relpath)
        t3cl.addWidget(self._top3, 1)
        exec_content.addWidget(top3_inner, 2)

        exec_outer.addLayout(exec_content, 1)
        self._dash_vl.addWidget(self._exec_card, 1)

        # --- Findings ledger card --------------------------------------------
        self._table_card = QFrame()
        self._table_card.setStyleSheet(
            f"QFrame{{ background:{PALETTE['bg_card']};border:1px solid {PALETTE['border']};"
            f"border-radius:8px; }}"
        )
        tcl = QVBoxLayout(self._table_card)
        tcl.setContentsMargins(12, 0, 12, 10)
        tcl.setSpacing(6)

        tbl_hdr = QFrame()
        tbl_hdr.setFixedHeight(34)
        tbl_hdr.setStyleSheet(
            f"background:{PALETTE['bg_elevated']};border-bottom:1px solid {PALETTE['border']};"
            f"border-radius:8px 8px 0 0;"
        )
        tbl_hdr_l = QHBoxLayout(tbl_hdr)
        tbl_hdr_l.setContentsMargins(12, 0, 8, 0)
        tbl_hdr_l.setSpacing(8)
        tbl_lbl = QLabel("Live Findings Ledger")
        tbl_lbl.setStyleSheet(f"font-size:11px;font-weight:bold;color:{PALETTE['accent_blue']};")
        tbl_hdr_l.addWidget(tbl_lbl)
        tbl_hdr_l.addStretch()

        self._rb_violations = QRadioButton("Violations Only")
        self._rb_violations.setChecked(True)
        self._rb_all = QRadioButton("All Findings")
        for rb in [self._rb_violations, self._rb_all]:
            rb.toggled.connect(self._update_findings_table)
            tbl_hdr_l.addWidget(rb)

        self._table_search = QLineEdit()
        self._table_search.setPlaceholderText("Search findings...")
        self._table_search.setFixedWidth(180)
        self._table_search.textChanged.connect(self._on_table_search)
        tbl_hdr_l.addWidget(self._table_search)

        self._btn_expand_table = QPushButton("[+]")
        self._btn_expand_table.setFixedSize(QSize(32, 20))
        self._btn_expand_table.setToolTip("Expand / restore this section")
        self._btn_expand_table.setStyleSheet(
            f"QPushButton{{background:transparent;color:{PALETTE['text_muted']};"
            f"border:none;font-size:11px;font-weight:bold;}}"
            f"QPushButton:hover{{color:{PALETTE['accent_blue']};}}"
        )
        self._btn_expand_table.clicked.connect(self._toggle_table_expand)
        tbl_hdr_l.addWidget(self._btn_expand_table)
        tcl.addWidget(tbl_hdr)

        cols = ["Severity", "Domain", "File Path", "Rule / Control Title", "Quick Remediation"]
        self._table = QTableWidget(0, len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setWordWrap(False)
        self._table.setColumnWidth(0, 100)
        self._table.setColumnWidth(1, 140)
        self._table.setColumnWidth(2, 300)
        self._table.setColumnWidth(3, 240)
        self._table.itemSelectionChanged.connect(self._on_table_selection_changed)
        self._table.itemDoubleClicked.connect(self._on_table_double_click)
        tcl.addWidget(self._table, 1)

        self._dash_vl.addWidget(self._table_card, 1)
        self._exec_expanded = False
        self._table_expanded = False
        return w

    # ── File Detail tab ────────────────────────────────────────────────────────
    def _build_file_detail_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top: file content viewer
        content_frame = QFrame()
        content_frame.setStyleSheet(
            f"QFrame{{ background:{PALETTE['bg_surface']};"
            f"border-bottom:1px solid {PALETTE['border']}; }}"
        )
        cfl = QVBoxLayout(content_frame)
        cfl.setContentsMargins(0, 0, 0, 0)
        cfl.setSpacing(0)

        file_hdr = QFrame()
        file_hdr.setFixedHeight(36)
        file_hdr.setStyleSheet(
            f"background:{PALETTE['bg_card']};border-bottom:1px solid {PALETTE['border']};"
        )
        fhhl = QHBoxLayout(file_hdr)
        fhhl.setContentsMargins(12, 0, 12, 0)
        self._file_path_lbl = QLabel("No file selected")
        self._file_path_lbl.setStyleSheet(
            f"font-family:monospace;font-size:11px;color:{PALETTE['text_secondary']};"
        )
        fhhl.addWidget(self._file_path_lbl, 1)
        self._btn_reveal_file = QPushButton("📂  Reveal in Explorer")
        self._btn_reveal_file.setEnabled(False)
        self._btn_reveal_file.clicked.connect(self._reveal_selected_file)
        fhhl.addWidget(self._btn_reveal_file)
        cfl.addWidget(file_hdr)

        self._file_content_viewer = QTextEdit()
        self._file_content_viewer.setReadOnly(True)
        self._file_content_viewer.setStyleSheet(
            f"font-family:'Consolas','JetBrains Mono',monospace;font-size:12px;"
            f"background:{PALETTE['bg_surface']};color:{PALETTE['text_primary']};"
        )
        self._file_content_viewer.setPlaceholderText(
            "Click a file in the tree or a row in the findings table to preview file content here."
        )
        cfl.addWidget(self._file_content_viewer, 1)
        splitter.addWidget(content_frame)

        # Bottom: finding detail panel
        detail_frame = QFrame()
        detail_frame.setStyleSheet(f"background:{PALETTE['bg_surface']};")
        dfl = QVBoxLayout(detail_frame)
        dfl.setContentsMargins(0, 0, 0, 0)
        dfl.setSpacing(0)

        detail_hdr = QFrame()
        detail_hdr.setFixedHeight(36)
        detail_hdr.setStyleSheet(
            f"background:{PALETTE['bg_card']};border-top:1px solid {PALETTE['border']};"
            f"border-bottom:1px solid {PALETTE['border']};"
        )
        dhhl = QHBoxLayout(detail_hdr)
        dhhl.setContentsMargins(12, 0, 12, 0)
        det_lbl = QLabel("🔍  Finding Detail & AI Remediation Advisory")
        det_lbl.setStyleSheet(f"font-weight:bold;font-size:12px;color:{PALETTE['accent_blue']};")
        dhhl.addWidget(det_lbl)
        dfl.addWidget(detail_hdr)

        self._detail_viewer = QTextEdit()
        self._detail_viewer.setReadOnly(True)
        self._detail_viewer.setAcceptRichText(True)
        self._detail_viewer.setPlaceholderText(
            "Select a finding row in the ledger to view full details and AI remediation advisory here."
        )
        dfl.addWidget(self._detail_viewer, 1)
        splitter.addWidget(detail_frame)

        splitter.setSizes([350, 280])
        vl.addWidget(splitter, 1)
        return w

    # ── Status bar ─────────────────────────────────────────────────────────────
    def _build_status_bar(self) -> QFrame:
        bar = QFrame()
        bar.setFixedHeight(26)
        bar.setStyleSheet(
            f"background:{PALETTE['bg_card']};border-top:1px solid {PALETTE['border']};"
        )
        hl = QHBoxLayout(bar)
        hl.setContentsMargins(16, 0, 16, 0)

        self._statusbar_lbl = QLabel("Kintsugi-GRC v2.0 — PyQt6 Edition")
        self._statusbar_lbl.setStyleSheet(f"font-size:10px;color:{PALETTE['text_muted']};")
        hl.addWidget(self._statusbar_lbl)
        hl.addStretch()

        domains = [
            "🔑 Privilege Mgmt", "🛡️ Data Protection",
            "⚙️ Vuln Control", "📦 Media Handling", "📋 Audit Logging"
        ]
        for d in domains:
            p = QLabel(f" {d} ")
            p.setStyleSheet(
                f"background:{PALETTE['bg_elevated']};color:{PALETTE['accent_cyan']};"
                f"font-size:9px;border-radius:3px;padding:2px 4px;"
            )
            hl.addWidget(p)

        return bar

    # ──────────────────────────────────────────────────────────────────────────
    # MONITORING CONTROL
    # ──────────────────────────────────────────────────────────────────────────

    def _toggle_monitoring(self):
        if self._is_monitoring:
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self):
        target = Path(self._target_edit.text().strip()).resolve()
        if not target.exists():
            QMessageBox.critical(self, "Invalid Directory",
                                 f"Target directory does not exist:\n{target}")
            return

        self._is_monitoring = True
        self._btn_monitor.setText("⏹  Stop Monitoring")
        self._btn_monitor.setObjectName("btnDanger")
        self._btn_monitor.setStyleSheet(
            f"QPushButton{{background:{PALETTE['red']};color:#fff;border:none;"
            f"border-radius:6px;padding:6px 16px;font-weight:bold;}}"
            f"QPushButton:hover{{background:#ff6b6b;}}"
        )
        self._btn_pdf.setEnabled(False)
        self._progress_bar.setValue(0)
        self._set_status_badge("scanning")

        self._worker = ScanWorker(
            target_dir=target,
            industry=self._industry_cb.currentText(),
            custom_policy=self._policy_edit.text().strip(),
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.scan_done.connect(self._on_scan_done)
        self._worker.scan_error.connect(self._on_scan_error)
        self._worker.dynamic_done.connect(self._on_dynamic_update)
        self._worker.start()

    def _stop_monitoring(self):
        if self._worker:
            self._worker.stop_watcher()
        self._is_monitoring = False
        self._btn_monitor.setText("▶  Start Monitoring")
        self._btn_monitor.setObjectName("btnPrimary")
        self._btn_monitor.setStyleSheet("")   # re-apply from stylesheet
        self._apply_stylesheet()
        self._set_status_badge("paused")
        self._progress_lbl.setText("Monitoring paused.")

    # ──────────────────────────────────────────────────────────────────────────
    # WORKER CALLBACKS
    # ──────────────────────────────────────────────────────────────────────────

    def _on_progress(self, pct: int, msg: str):
        self._progress_bar.setValue(pct)
        self._progress_lbl.setText(f"{pct}%  —  {msg}")

    def _on_scan_done(self, summary: Dict):
        self.scan_summary = summary
        self._btn_pdf.setEnabled(True)
        score = summary.get("compliance_score", 0)
        self._score_lbl.setText(f"{score}%")
        files = summary.get("total_files_scanned", 0)
        target = summary.get("target_directory", "")
        self._progress_lbl.setText(
            f"✅  Monitoring {files} files in {target} — Score: {score}%"
        )
        crits = summary.get("severity_counts", {}).get("CRITICAL", 0)
        highs = summary.get("severity_counts", {}).get("HIGH", 0)
        if crits + highs == 0:
            self._set_status_badge("ok")
        else:
            self._set_status_badge("alert", crits + highs)

        self._refresh_all(summary)

    def _on_scan_error(self, err: str):
        self._is_monitoring = False
        self._btn_monitor.setText("▶  Start Monitoring")
        self._apply_stylesheet()
        self._set_status_badge("error")
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scan:\n{err}")

    def _on_dynamic_update(self, summary: Dict, msg: str):
        self.scan_summary = summary
        score = summary.get("compliance_score", 0)
        self._score_lbl.setText(f"{score}%")
        self._progress_lbl.setText(msg)
        crits = summary.get("severity_counts", {}).get("CRITICAL", 0)
        highs = summary.get("severity_counts", {}).get("HIGH", 0)
        if crits + highs == 0:
            self._set_status_badge("ok")
        else:
            self._set_status_badge("alert", crits + highs)
        self._refresh_all(summary)

    # ──────────────────────────────────────────────────────────────────────────
    # STATUS BADGE
    # ──────────────────────────────────────────────────────────────────────────

    def _set_status_badge(self, state: str, count: int = 0):
        styles = {
            "ok":       (f"background:{PALETTE['green_bg']};color:{PALETTE['green']};",
                         "  🟢  Protection Active  "),
            "alert":    (f"background:{PALETTE['red_bg']};color:{PALETTE['red']};",
                         f"  ⚠️  {count} Active Violations  "),
            "scanning": (f"background:{PALETTE['yellow_bg']};color:{PALETTE['yellow']};",
                         "  🔄  Scanning...  "),
            "paused":   (f"background:{PALETTE['bg_elevated']};color:{PALETTE['text_secondary']};",
                         "  🟡  Monitoring Paused  "),
            "error":    (f"background:{PALETTE['red_bg']};color:{PALETTE['red']};",
                         "  🔴  Protection Error  "),
        }
        style, text = styles.get(state, styles["paused"])
        self._status_badge.setStyleSheet(
            style + "font-weight:bold;font-size:12px;border-radius:16px;padding:6px 14px;"
        )
        self._status_badge.setText(text)

    # ──────────────────────────────────────────────────────────────────────────
    # REFRESH ALL UI COMPONENTS
    # ──────────────────────────────────────────────────────────────────────────

    def _refresh_all(self, summary: Dict):
        sev_counts = summary.get("severity_counts", {})
        findings   = summary.get("findings", [])

        self._donut.update_data(sev_counts, self._filter_severity)
        self._legend.update_data(sev_counts, self._filter_severity)
        self._top3.update_issues(findings, self._filter_severity)
        self._rebuild_file_tree(findings)
        self._update_findings_table()

    # ──────────────────────────────────────────────────────────────────────────
    # FILE TREE
    # ──────────────────────────────────────────────────────────────────────────

    def _rebuild_file_tree(self, findings: List[Dict]):
        self._file_tree.clear()
        if not findings:
            return

        # Build a nested severity map: dir → file → [severities]
        tree_map: Dict[str, Dict[str, List[str]]] = {}
        for f in findings:
            rel = f.get("file_path", "unknown")
            p   = Path(rel)
            folder = p.parent.as_posix() if p.parent.as_posix() != "." else "(root)"
            fname  = p.name
            tree_map.setdefault(folder, {}).setdefault(fname, [])
            tree_map[folder][fname].append(f.get("severity", "PASS"))

        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "PASS": 1}

        def worst(sevs):
            return max(sevs, key=lambda s: sev_rank.get(s, 0))

        def color_for(sev):
            return SEV_COLOR.get(sev, PALETTE["text_secondary"])

        for folder, files in sorted(tree_map.items()):
            folder_worst = worst([worst(s) for s in files.values()])
            folder_item  = QTreeWidgetItem([f"📁  {folder}"])
            folder_item.setForeground(0, QBrush(QColor(color_for(folder_worst))))
            folder_item.setFont(0, QFont("Segoe UI", 11, QFont.Weight.Bold))
            folder_item.setData(0, Qt.ItemDataRole.UserRole, {"type": "folder", "path": folder})

            for fname, sevs in sorted(files.items()):
                w_sev  = worst(sevs)
                icons  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "PASS": "🟢"}
                icon   = icons.get(w_sev, "⚪")
                file_item = QTreeWidgetItem([f"{icon}  {fname}"])
                file_item.setForeground(0, QBrush(QColor(color_for(w_sev))))
                file_item.setFont(0, QFont("Segoe UI", 10))
                # Attach data so we can filter findings on click
                rel_paths = [
                    f["file_path"] for f in findings
                    if Path(f["file_path"]).name == fname
                ]
                file_item.setData(
                    0, Qt.ItemDataRole.UserRole,
                    {"type": "file", "name": fname, "rel_paths": rel_paths}
                )
                folder_item.addChild(file_item)

            self._file_tree.addTopLevelItem(folder_item)

        self._file_tree.expandAll()

    def _filter_file_tree(self, text: str):
        """Show/hide tree items based on search text."""
        text = text.lower()
        for i in range(self._file_tree.topLevelItemCount()):
            folder_item = self._file_tree.topLevelItem(i)
            any_visible = False
            for j in range(folder_item.childCount()):
                child = folder_item.child(j)
                match = text in child.text(0).lower()
                child.setHidden(not match)
                if match:
                    any_visible = True
            folder_item.setHidden(not any_visible and bool(text))

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, col: int):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or not self.scan_summary:
            return

        if data.get("type") == "file":
            # Show findings for this file and load content
            rel_paths = data.get("rel_paths", [])
            file_findings = [
                f for f in self.scan_summary.get("findings", [])
                if f.get("file_path") in rel_paths
            ]
            if file_findings:
                self._load_file_detail(file_findings[0], auto_switch_tab=True)

    # ──────────────────────────────────────────────────────────────────────────
    # FINDINGS TABLE
    # ──────────────────────────────────────────────────────────────────────────

    def _update_findings_table(self):
        if not self.scan_summary:
            return
        findings = self.scan_summary.get("findings", [])
        violations_only = self._rb_violations.isChecked()
        search = self._table_search.text().lower()

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        self.displayed_findings.clear()

        for f in findings:
            sev = f.get("severity", "PASS")
            if violations_only and sev == "PASS":
                continue
            if self._filter_severity and sev != self._filter_severity:
                continue

            rule_id  = f.get("rule_id", "")
            title    = f.get("title", "")
            fp       = f.get("file_path", "")
            domain   = DOMAIN_NAMES.get(rule_id, "⚙️ System Config")
            advisory = f.get("rag_advisory", {})
            rem      = advisory.get("remediation_command", REMEDIATION_HINTS.get(rule_id, "Review finding"))

            # Text search
            searchable = f"{sev} {fp} {title} {domain} {rem}".lower()
            if search and search not in searchable:
                continue

            self.displayed_findings.append(f)
            row_i = self._table.rowCount()
            self._table.insertRow(row_i)

            # Severity cell
            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(QBrush(QColor(SEV_COLOR.get(sev, PALETTE["text_secondary"]))))
            sev_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(row_i, 0, sev_item)

            # Domain
            dom_item = QTableWidgetItem(domain)
            dom_item.setForeground(QBrush(QColor(PALETTE["text_secondary"])))
            dom_item.setFont(QFont("Segoe UI", 10))
            self._table.setItem(row_i, 1, dom_item)

            # File path
            fp_item = QTableWidgetItem(fp)
            fp_item.setForeground(QBrush(QColor(PALETTE["accent_cyan"])))
            fp_item.setFont(QFont("Consolas", 10))
            self._table.setItem(row_i, 2, fp_item)

            # Title
            title_item = QTableWidgetItem(title)
            title_item.setForeground(QBrush(QColor(PALETTE["text_primary"])))
            self._table.setItem(row_i, 3, title_item)

            # Remediation
            rem_item = QTableWidgetItem(rem)
            rem_item.setForeground(QBrush(QColor(PALETTE["text_secondary"])))
            rem_item.setFont(QFont("Consolas", 10))
            self._table.setItem(row_i, 4, rem_item)

            # Row background tint
            bg = QColor(SEV_BG.get(sev, PALETTE["bg_surface"]))
            for ci in range(5):
                it = self._table.item(row_i, ci)
                if it:
                    it.setBackground(QBrush(bg))

        self._table.setSortingEnabled(True)
        self._table.resizeRowsToContents()

    def _on_table_search(self, text: str):
        self._filter_text = text
        self._update_findings_table()

    def _on_table_selection_changed(self):
        rows = self._table.selectedItems()
        if not rows:
            return
        row_i = self._table.currentRow()
        if 0 <= row_i < len(self.displayed_findings):
            self._load_file_detail(self.displayed_findings[row_i])

    def _on_table_double_click(self, item: QTableWidgetItem):
        row_i = item.row()
        if 0 <= row_i < len(self.displayed_findings):
            finding = self.displayed_findings[row_i]
            target  = Path(self._target_edit.text().strip()).resolve()
            dlg     = FindingDetailDialog(finding, target, self)
            dlg.exec()

    # -------------------------------------------------------------------------
    # EXPAND / COLLAPSE DASHBOARD SECTIONS
    # -------------------------------------------------------------------------

    def _toggle_exec_expand(self):
        """Expand executive summary to fill the dashboard, or restore both sections."""
        if self._exec_expanded:
            # Restore both
            self._exec_card.setVisible(True)
            self._exec_card.setMaximumHeight(16777215)
            self._table_card.setVisible(True)
            self._dash_vl.setStretch(0, 1)
            self._dash_vl.setStretch(1, 1)
            self._btn_expand_exec.setText("[+]")
            self._btn_expand_table.setText("[+]")
            self._exec_expanded = False
            self._table_expanded = False
        else:
            # Expand exec, collapse table
            self._exec_card.setMaximumHeight(16777215)
            self._table_card.setVisible(False)
            self._dash_vl.setStretch(0, 1)
            self._dash_vl.setStretch(1, 0)
            self._btn_expand_exec.setText("[-]")
            self._exec_expanded = True
            self._table_expanded = False

    def _toggle_table_expand(self):
        """Expand findings ledger to fill the dashboard, or restore both sections."""
        if self._table_expanded:
            # Restore both
            self._exec_card.setVisible(True)
            self._exec_card.setMaximumHeight(16777215)
            self._table_card.setVisible(True)
            self._dash_vl.setStretch(0, 1)
            self._dash_vl.setStretch(1, 1)
            self._btn_expand_exec.setText("[+]")
            self._btn_expand_table.setText("[+]")
            self._exec_expanded = False
            self._table_expanded = False
        else:
            # Expand table, collapse exec
            self._exec_card.setVisible(False)
            self._table_card.setVisible(True)
            self._dash_vl.setStretch(0, 0)
            self._dash_vl.setStretch(1, 1)
            self._btn_expand_table.setText("[-]")
            self._table_expanded = True
            self._exec_expanded = False


    # ──────────────────────────────────────────────────────────────────────────
    # SEVERITY FILTER
    # ──────────────────────────────────────────────────────────────────────────

    def _on_severity_filter(self, severity: str):
        if severity == "ALL" or self._filter_severity == severity:
            self._filter_severity = None
            self._btn_reset_filter.setVisible(False)
        else:
            self._filter_severity = severity
            self._btn_reset_filter.setVisible(True)

        if self.scan_summary:
            self._refresh_all(self.scan_summary)

    # ──────────────────────────────────────────────────────────────────────────
    # FILE DETAIL VIEWER
    # ──────────────────────────────────────────────────────────────────────────

    def _load_file_detail(self, finding: Dict, auto_switch_tab: bool = False):
        self._selected_finding = finding
        rel_path   = finding.get("file_path", "")
        target_dir = Path(self._target_edit.text().strip()).resolve()
        full_path  = (target_dir / rel_path).resolve()

        # Update path label
        self._file_path_lbl.setText(str(full_path))
        self._btn_reveal_file.setEnabled(True)

        # Load file content (first 1000 lines or 100KB)
        self._file_content_viewer.clear()
        if full_path.exists() and full_path.is_file():
            try:
                size = full_path.stat().st_size
                if size > 200 * 1024:
                    self._file_content_viewer.setPlainText(
                        f"[File too large to preview — {size/1024:.0f} KB]\n"
                        f"Click '📂 Reveal in Explorer' to open externally."
                    )
                else:
                    content = full_path.read_text(encoding="utf-8", errors="replace")
                    lines   = content.splitlines()[:1000]
                    self._file_content_viewer.setPlainText("\n".join(lines))
            except Exception as e:
                self._file_content_viewer.setPlainText(f"[Unable to read file: {e}]")
        else:
            self._file_content_viewer.setPlainText(
                f"[File not found on disk: {full_path}]\n\n"
                "The file may have been deleted or moved since scanning."
            )

        # Populate detail panel with rich HTML
        self._populate_detail_html(finding)

        if auto_switch_tab:
            self._tabs.setCurrentIndex(1)

    def _populate_detail_html(self, f: Dict):
        sev      = f.get("severity", "INFO")
        title    = f.get("title", "Security Finding")
        rule_id  = f.get("rule_id", "N/A")
        fp       = f.get("file_path", "N/A")
        desc     = f.get("description", "No description.")
        details  = f.get("details", {})
        mappings = f.get("framework_mappings", [])
        advisory = f.get("rag_advisory", {})

        color  = SEV_COLOR.get(sev, PALETTE["text_secondary"])
        bgc    = SEV_BG.get(sev, PALETTE["bg_surface"])
        acc    = PALETTE["accent_blue"]
        dim    = PALETTE["text_secondary"]
        code   = PALETTE["bg_elevated"]
        txt    = PALETTE["text_primary"]

        html_parts = [
            f"<div style='font-family:\"Segoe UI\",sans-serif;font-size:12px;color:{txt};'>",
            # Severity badge + title
            f"<p style='margin:0 0 4px 0;'>"
            f"<span style='background:{color};color:#000;padding:2px 8px;border-radius:4px;"
            f"font-weight:bold;font-size:11px;'>{sev}</span>"
            f"&nbsp;&nbsp;<span style='font-weight:bold;font-size:14px;'>{title}</span></p>",
            f"<p style='margin:0 0 8px 0;color:{dim};font-size:10px;font-family:monospace;'>"
            f"Rule: {rule_id} &nbsp;|&nbsp; {fp}</p>",
            f"<hr style='border:none;border-top:1px solid {PALETTE['border']};margin:8px 0;'>",
            # Description
            f"<p style='color:{acc};font-weight:bold;margin:6px 0 2px;'>📌 Finding Description</p>",
            f"<p style='color:{txt};margin:0 0 8px;'>{desc}</p>",
        ]

        biz = details.get("business_explanation") or advisory.get("business_explanation", "")
        if biz:
            html_parts += [
                f"<p style='color:{acc};font-weight:bold;margin:6px 0 2px;'>🛡️ Business Risk</p>",
                f"<p style='color:{txt};margin:0 0 8px;'>{biz}</p>",
            ]

        tech = {k: v for k, v in details.items() if k != "business_explanation"}
        if tech:
            html_parts += [
                f"<p style='color:{acc};font-weight:bold;margin:6px 0 2px;'>⚙️ Technical Parameters</p>",
                f"<pre style='background:{code};border-radius:5px;padding:6px 10px;"
                f"font-size:11px;color:{acc};white-space:pre-wrap;margin:0 0 8px;'>"
                f"{json.dumps(tech, indent=2)}</pre>",
            ]

        if mappings:
            html_parts.append(
                f"<p style='color:{acc};font-weight:bold;margin:6px 0 2px;'>📜 GRC Framework Citations</p>"
            )
            for m in mappings:
                fw   = m.get("framework", "GRC")
                cid  = m.get("control_id", "N/A")
                ctit = m.get("title", "Requirement")
                st   = m.get("status", "REVIEW")
                html_parts.append(
                    f"<p style='margin:2px 0;'>• <b style='color:{acc};'>[{fw}] {cid}</b>:"
                    f" {ctit} <span style='color:{dim};'>({st})</span></p>"
                )
            html_parts.append("<br>")

        if advisory:
            cmd = advisory.get("remediation_command", "")
            html_parts += [
                f"<p style='color:{acc};font-weight:bold;margin:6px 0 2px;'>🤖 RAG AI Remediation Advisory</p>",
                f"<p style='margin:2px 0;'><span style='color:{dim};'>Clause ID:</span> {advisory.get('clause_id','—')}</p>",
                f"<p style='margin:2px 0;'><span style='color:{dim};'>Standard:</span>  {advisory.get('standard','—')}</p>",
                f"<p style='margin:2px 0;'><span style='color:{dim};'>Risk:</span>      {advisory.get('risk_statement','—')}</p>",
            ]
            if cmd:
                html_parts.append(
                    f"<p style='margin:4px 0;'><span style='color:{dim};'>Command:</span><br>"
                    f"<code style='background:{code};padding:4px 8px;border-radius:4px;"
                    f"color:{acc};font-size:11px;'>{cmd}</code></p>"
                )
            if advisory.get("rationale"):
                html_parts.append(
                    f"<p style='margin:2px 0;'><span style='color:{dim};'>Rationale:</span> {advisory['rationale']}</p>"
                )

        html_parts.append("</div>")
        self._detail_viewer.setHtml("".join(html_parts))

    # ──────────────────────────────────────────────────────────────────────────
    # FILE EXPLORER HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def _reveal_selected_file(self):
        if self._selected_finding:
            rel  = self._selected_finding.get("file_path", "")
            root = Path(self._target_edit.text().strip()).resolve()
            full = (root / rel).resolve()
            reveal_in_file_explorer(full if full.exists() else root)

    def _reveal_by_relpath(self, rel_path: str):
        root = Path(self._target_edit.text().strip()).resolve()
        full = (root / rel_path).resolve()
        reveal_in_file_explorer(full if full.exists() else root)

    def _browse_target(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Select Target Directory to Monitor",
            self._target_edit.text()
        )
        if folder:
            self._target_edit.setText(folder)

    def _open_target_in_explorer(self):
        target = Path(self._target_edit.text().strip()).resolve()
        reveal_in_file_explorer(target)

    def _upload_policy(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Upload Custom Policy Document", "",
            "Policy Files (*.json *.txt *.md);;All Files (*.*)"
        )
        if path:
            if Path(path).stat().st_size > 10 * 1024 * 1024:
                QMessageBox.warning(self, "File Too Large",
                                    "Policy file must be under 10 MB.")
                return
            self._policy_edit.setText(path)

    def _export_pdf(self):
        if not self.scan_summary:
            QMessageBox.warning(self, "No Data",
                                "Run a scan first before exporting PDF.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PDF Report", "scan_report.pdf",
            "PDF Documents (*.pdf)"
        )
        if path:
            out = Path(path)
            PDFComplianceExporter.generate_pdf_report(self.scan_summary, out)
            QMessageBox.information(self, "PDF Exported",
                                    f"Compliance report saved:\n{out}")

    # ──────────────────────────────────────────────────────────────────────────
    # CLOSE EVENT
    # ──────────────────────────────────────────────────────────────────────────
    def closeEvent(self, event):
        if self._worker:
            self._worker.stop_watcher()
        event.accept()


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def launch_pyqt_gui():
    """Launches Kintsugi-GRC PyQt6 desktop application."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Kintsugi-GRC")
    app.setApplicationVersion("2.0")
    app.setStyle("Fusion")
    apply_dark_palette(app)

    window = KintsugiGRCApp()
    window.show()
    sys.exit(app.exec())
