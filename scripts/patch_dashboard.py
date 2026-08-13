"""Patch script: rewrites _build_dashboard_tab in interface.py using line-number slicing."""
from pathlib import Path

src = Path("/Users/dennislay/Downloads/kintsugi-grc/src/ui/interface.py")
lines = src.read_text(encoding="utf-8").splitlines(keepends=True)

# Verify expected boundaries (1-indexed)
assert "def _build_dashboard_tab" in lines[1149], f"Unexpected line 1150: {lines[1149]!r}"
assert "File Detail tab" in lines[1269], f"Unexpected line 1270: {lines[1269]!r}"

before = lines[:1148]       # lines 1-1148 (before the comment + def)
after  = lines[1269:]       # lines 1270+ (file detail tab comment onward)

NEW_METHOD = '''\
    # -- Dashboard tab -------------------------------------------------------
    def _build_dashboard_tab(self) -> QWidget:
        w = QWidget()
        self._dash_vl = QVBoxLayout(w)
        self._dash_vl.setContentsMargins(12, 12, 12, 12)
        self._dash_vl.setSpacing(8)

        # --- Executive summary card -----------------------------------------
        self._exec_card = QFrame()
        self._exec_card.setStyleSheet(
            f"QFrame{{ background:{PALETTE[\'bg_card\']};border:1px solid {PALETTE[\'border\']};"
            f"border-radius:8px; }}"
        )
        self._exec_card.setMaximumHeight(210)
        exec_outer = QVBoxLayout(self._exec_card)
        exec_outer.setContentsMargins(0, 0, 0, 0)
        exec_outer.setSpacing(0)

        exec_hdr = QFrame()
        exec_hdr.setFixedHeight(30)
        exec_hdr.setStyleSheet(
            f"background:{PALETTE[\'bg_elevated\']};border-bottom:1px solid {PALETTE[\'border\']};"
            f"border-radius:8px 8px 0 0;"
        )
        exec_hdr_l = QHBoxLayout(exec_hdr)
        exec_hdr_l.setContentsMargins(12, 0, 8, 0)
        exec_ttl = QLabel("Executive Summary")
        exec_ttl.setStyleSheet(
            f"font-size:11px;font-weight:bold;color:{PALETTE[\'text_secondary\']};"
        )
        exec_hdr_l.addWidget(exec_ttl, 1)
        self._btn_expand_exec = QPushButton("[+]")
        self._btn_expand_exec.setFixedSize(QSize(32, 20))
        self._btn_expand_exec.setToolTip("Expand / restore this section")
        self._btn_expand_exec.setStyleSheet(
            f"QPushButton{{background:transparent;color:{PALETTE[\'text_muted\']};"
            f"border:none;font-size:11px;font-weight:bold;}}"
            f"QPushButton:hover{{color:{PALETTE[\'accent_blue\']};}}"
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
        div.setStyleSheet(f"color:{PALETTE[\'border\']};")
        exec_content.addWidget(div)

        top3_inner = QFrame()
        top3_inner.setStyleSheet("QFrame{background:transparent;}")
        t3cl = QVBoxLayout(top3_inner)
        t3cl.setContentsMargins(4, 0, 0, 0)
        t3cl.setSpacing(4)
        t3_hdr = QHBoxLayout()
        t3_title = QLabel("Top 3 Priority Issues")
        t3_title.setStyleSheet(f"font-size:12px;font-weight:bold;color:{PALETTE[\'red\']};")
        t3_hdr.addWidget(t3_title, 1)
        self._btn_reset_filter = QPushButton("Reset")
        self._btn_reset_filter.setFixedHeight(20)
        self._btn_reset_filter.setStyleSheet(
            f"QPushButton{{background:{PALETTE[\'bg_elevated\']};color:{PALETTE[\'accent_blue\']};"
            f"border:1px solid {PALETTE[\'border\']};border-radius:4px;padding:0 6px;font-size:10px;}}"
            f"QPushButton:hover{{border-color:{PALETTE[\'accent_blue\']};}}"
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
            f"QFrame{{ background:{PALETTE[\'bg_card\']};border:1px solid {PALETTE[\'border\']};"
            f"border-radius:8px; }}"
        )
        tcl = QVBoxLayout(self._table_card)
        tcl.setContentsMargins(12, 0, 12, 10)
        tcl.setSpacing(6)

        tbl_hdr = QFrame()
        tbl_hdr.setFixedHeight(34)
        tbl_hdr.setStyleSheet(
            f"background:{PALETTE[\'bg_elevated\']};border-bottom:1px solid {PALETTE[\'border\']};"
            f"border-radius:8px 8px 0 0;"
        )
        tbl_hdr_l = QHBoxLayout(tbl_hdr)
        tbl_hdr_l.setContentsMargins(12, 0, 8, 0)
        tbl_hdr_l.setSpacing(8)
        tbl_lbl = QLabel("Live Findings Ledger")
        tbl_lbl.setStyleSheet(f"font-size:11px;font-weight:bold;color:{PALETTE[\'accent_blue\']};")
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
            f"QPushButton{{background:transparent;color:{PALETTE[\'text_muted\']};"
            f"border:none;font-size:11px;font-weight:bold;}}"
            f"QPushButton:hover{{color:{PALETTE[\'accent_blue\']};}}"
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

        self._dash_vl.addWidget(self._table_card, 4)
        self._exec_expanded = False
        self._table_expanded = False
        return w

'''

result = before + [NEW_METHOD] + after
src.write_text("".join(result), encoding="utf-8")
print(f"Done. Total lines: {sum(1 for _ in open(src))}")
