# Kintsugi-GRC (Phase 2 MVP Runtime Platform)

## 1. Project Overview & Launch Model
Kintsugi-GRC operates as a single-program utility that boots a local PyQt6 desktop GUI while verifying a background Docker RAG pipeline container. The application runs read-only recursive target sweeps, flags shadow access permissions extending beyond operational requirements, and maps technical discoveries to authoritative framework controls (HIPAA, PCI DSS, NIST, HITRUST CSF).

## 2. Core Execution Steps
1. **Launch Program**: Initializes `app.py`, spinning up the PyQt6 desktop GUI and checking the background `kintsugi-rag-pipeline` Docker container.
2. **Directory Selection**: The operator provides a target local system path via the GUI file browser or the `--target` CLI flag.
3. **Recursive Sweep**: The file scanning engine processes local nodes using multi-attribute heuristic tests — regex data parsing, Shannon entropy calculation, Luhn-10 PAN validation, and GPG magic byte verification.
4. **Access Verification**: The tool maps local UIDs/GIDs against host user-group sheets to evaluate cross-department shadow access exposures.
5. **Policy Degradation**: Evaluates discoveries against an internal `policy.json` config map. If missing or corrupt, it automatically falls back to default systemic thresholds.
6. **RAG Contextualization & Mapping**: Resolves failed tests against compliance frameworks (HIPAA §164.312, PCI DSS v4.0, NIST SP 800-53, HITRUST CSF v11.8.0) using local FAISS vector matching.
7. **Advisory Compliance Output**: Renders findings in the interactive GUI dashboard — including a clickable severity donut chart, sortable findings ledger, file content viewer, and AI remediation advisory panel — and exports a structured PDF compliance report.

## 3. Run Modes

```bash
# Launch PyQt6 Desktop GUI (default on macOS/display)
python3 app.py gui
python3 app.py          # auto-detects display

# CLI: full recursive scan with JSON + PDF output
python3 app.py scan --target ./synthetic_test_env --industry Healthcare

# CLI: re-generate PDF from existing scan JSON
python3 app.py export-pdf --report scan_report.json

# CLI: validate scan against expected QA assertions
python3 app.py verify-expected --target ./synthetic_test_env

# CLI: print terminal compliance dashboard from existing report
python3 app.py summary --report scan_report.json

# Optional flags (scan mode)
#   --watch / -w      Enable real-time dynamic directory watcher
#   --verbose / -v    Enable DEBUG logging
```

## 4. GUI Features (PyQt6)
* **Dark-mode dashboard** — deep dark-slate theme with premium typography
* **Interactive file tree** — hierarchical nodes color-coded 🔴/🟠/🟡/🟢 by worst severity per file/folder
* **Severity donut chart** — clickable slices filter the findings ledger
* **Top 3 priority issues** — color-coded urgent action cards with quick reveal buttons
* **Live findings ledger** — sortable, searchable `QTableWidget` with row-level severity tinting
* **File detail viewer** — read-only file content preview + rich HTML finding detail & RAG advisory panel
* **Double-click modal** — full `QDialog` with framework citations (HIPAA/PCI DSS/NIST), technical parameters, and remediation commands
* **Dynamic watcher** — background `QThread` + `pyqtSignal` architecture; file edits re-scan in real time
* **PDF export** — native `QFileDialog` save-as via `PDFComplianceExporter`
* **Custom policy upload** — JSON/text company policy vectorized into FAISS index on-the-fly

## 5. Dependencies
```
numpy>=1.26.4
faiss-cpu>=1.8.0
sentence-transformers>=3.0.1
PyQt6>=6.6.0
PyQt6-Charts>=6.6.0
```

## 6. Team Roles & Code Ownership Matrix
* **Dennis Lay (Scrum Master)**: Core runtime orchestration (`app.py`), PyQt6 desktop GUI (`src/ui/`), shared environment configuration, continuous validation scripts, expected-vs-actual matrices, and pipeline integration tracking.
* **Aryan Seyam (Deliverable Architect)**: RAG pipeline (`src/rag/`), cryptographic indicators, Shannon entropy analysis, and permission aggregation logic (`src/scanner/`).
* **Tenzin Phuntsok (Project Coordinator)**: Dataset normalization, canonical framework JSON schemas, and vector DB indexing (`src/mapping/`).
* **Danna Gomez (Tech Auditor)**: APA reference auditing (`tests/`).

## 7. Branching Policies & Commit Conventions
* **Branch Pattern**: Use `[type]/[owner_firstname]-[short_description]`
  * Features: `feat/aryan-shadow-access`
  * Bug Fixes: `fix/danna-entropy-bounds`
  * Documentation/Data: `docs/tenzin-nist-normalization`
* **Commit Suffixes**: Format all messages cleanly matching structural ownership scope:
  * `feat(ui): migrate desktop GUI from Tkinter to PyQt6 with dark-mode interface`
  * `fix(scanner): enforce absolute read-only boundary flags on local traversals`
* **Merge Criteria**: Pushing code directly to the main branch is strictly prohibited. Development requires a Pull Request (PR) linked to an active Jira tracking issue, an automated test pass, and a review signoff.

## 8. License
This project is open-source software licensed under the [MIT License](LICENSE).
