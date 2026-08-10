# Kintsugi-GRC (Phase 2 MVP Runtime Platform)

## 1. Project Overview & Launch Model
Kintsugi-GRC operates as a single-program utility that boots a local user interface while verifying a background Docker RAG pipeline container. The application runs read-only recursive target sweeps, flags shadow access permissions extending beyond operational requirements, and maps technical discoveries to authoritative framework controls.

## 2. Core Execution Steps
1. **Launch Program**: Initializes `app.py`, spinning up the desktop GUI and checking the background `kintsugi-rag-pipeline` Docker container.
2. **Directory Selection**: The operator provides a target local system path.
3. **Recursive Sweep**: The file scanning engine processes local nodes using multi-attribute heuristic tests (regex data parsing + Shannon entropy calculation).
4. **Access Verification**: The tool maps local UIDs/GIDs against host user-group sheets to evaluate cross-department shadow access exposures.
5. **Policy Degradation**: Evaluates discoveries against an internal `policy.json` config map. If missing or corrupt, it automatically falls back to default systemic thresholds.
6. **RAG Contextualization & Mapping**: Resolves failed tests against compliance frameworks (HIPAA, PCI DSS, NIST) using local vector matching.
7. **Advisory Compliance Output**: Renders clickable directory hyperlinks inside the desktop GUI and exports a repeatable PDF report.

## 3. Team Roles & Code Ownership Matrix
* **Dennis Lay (Scrum Master)**: Core runtime orchestration, shared environment configuration, and pipeline integration tracking.
* **Aryan Seyam (Deliverable Architect)**: Technical file scanner, cryptographic indicators, and permission aggregation logic (`src/scanner/`).
* **Tenzin Phuntsok (Project Coordinator)**: Dataset normalization, canonical framework JSON schemas, and vector DB indexing (`src/mapping/`).
* **Danna Gomez (Tech Auditor)**: Continuous validation scripts, expected-vs-actual matrices, and APA reference auditing (`tests/`).

## 4. Branching Policies & Commit Conventions
* **Branch Pattern**: Use `[type]/[owner_firstname]-[short_description]` 
  * Features: `feat/aryan-shadow-access`
  * Bug Fixes: `fix/danna-entropy-bounds`
  * Documentation/Data: `docs/tenzin-nist-normalization`
* **Commit Suffixes**: Format all messages cleanly matching structural ownership scope:
  * `feat(ui): append clickable filesystem hyperlink handler routines`
  * `fix(scanner): enforce absolute read-only boundary flags on local traversals`
* **Merge Criteria**: Pushing code directly to the main branch is strictly prohibited. Development requires a Pull Request (PR) linked to an active Jira tracking issue, an automated test pass, and a review signoff.
