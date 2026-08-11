"""
Kintsugi-GRC Relational RAG Orchestrator (Aryan's Component)
Combines FAISS vector similarity search, SQLite relational clause queries, 
and deterministic fallbacks to generate structured compliance advisories.
"""

import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional
from src.database import DB_PATH, init_db

logger = logging.getLogger("kintsugi_rag_orchestrator")

try:
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer
    HAS_ML_RAG = True
except ImportError:
    faiss = None
    np = None
    SentenceTransformer = None
    HAS_ML_RAG = False


class RelationalRAGOrchestrator:
    """RAG Orchestrator mapping technical scan violations to compliance clauses and remediation commands."""

    def __init__(
        self,
        index_path: str = "imports/compliance_index.faiss",
        db_path: str = DB_PATH,
        model_name: str = "BAAI/bge-large-en-v1.5",
        cache_dir: str = "./.model_cache"
    ):
        self.db_path = db_path
        self.index_path = index_path
        self.model = None
        self.index = None
        self.ml_ready = False

        # Make sure DB is initialized
        init_db(self.db_path)

        # Attempt to load ML model and FAISS index if dependencies present
        if HAS_ML_RAG and os.path.exists(index_path):
            try:
                os.makedirs(cache_dir, exist_ok=True)
                self.model = SentenceTransformer(model_name, cache_folder=cache_dir)
                self.index = faiss.read_index(index_path)
                self.ml_ready = True
                logger.info(f"Loaded FAISS vector index '{index_path}' & SentenceTransformer model '{model_name}'.")
            except Exception as e:
                logger.debug(f"ML RAG index initialization skipped ({e}). Falling back to relational SQLite lookup.")

        # Comprehensive Fallback & Rule Advisory Dictionary
        self.fallback_dictionary = {
            "ERR-OCTAL-WORLD-WRITABLE": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2",
                "risk_statement": "System file contains world-writable permissions (0o777), violating access controls.",
                "remediation_command": "chmod 640 {filepath}",
                "rationale": "Restrict file permissions using owner/group boundaries."
            },
            "ERR-ENTROPY-PLAINTEXT-PII": {
                "clause_id": "HIPAA-164-312-A2-IV / PCI-DSS-V4-REQ-3-5-1 / CUSTOM-POLICY-CHUNK-0",
                "standard": "HIPAA §164.312(a)(2)(iv) & PCI-DSS v4.0.1 Req 3.5.1",
                "risk_statement": "Cleartext sensitive records detected in unencrypted file payload.",
                "remediation_command": "gpg --symmetric --cipher-algo AES256 {filepath}",
                "rationale": "Encrypt file using GPG/AES symmetric encryption."
            },
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2.1",
                "risk_statement": "File permissions '0o777' allow world-writable access to sensitive payloads, violating Least Privilege.",
                "remediation_command": "chmod 640 {filepath}",
                "rationale": "Restrict file permissions using owner/group boundaries per HIPAA §164.312(a)(1) and PCI-DSS Requirement 7.2.1."
            },
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": {
                "clause_id": "HIPAA-164-312-A2-IV / PCI-DSS-V4-REQ-3-5-1",
                "standard": "HIPAA §164.312(a)(2)(iv) & PCI-DSS v4.0.1 Req 3.5.1",
                "risk_statement": "File contains unencrypted cleartext sensitive records (Luhn PAN credit cards or SSNs).",
                "remediation_command": "gpg --symmetric --cipher-algo AES256 {filepath}",
                "rationale": "Encrypt stored sensitive records using AES-256 with OpenSSL magic header header formatting."
            },
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": {
                "clause_id": "PCI-DSS-V4-REQ-2-2-4 / NIST-800-53-CM-6",
                "standard": "PCI-DSS v4.0.1 Req 2.2.4 & NIST 800-53 CM-6",
                "risk_statement": "SSH server configuration allows legacy Protocol 1 or weak ciphers (Blowfish/3DES).",
                "remediation_command": "sed -i 's/Protocol 1/Protocol 2/' {filepath} && systemctl restart sshd",
                "rationale": "Enforce SSH Protocol 2 and mandate strong AES/CTR cipher suites."
            },
            "INSECURE_SYSTEM_TLS_POLICY": {
                "clause_id": "PCI-DSS-V4-REQ-4-2-1 / HIPAA-164-312-E1",
                "standard": "PCI-DSS v4.0.1 Req 4.2.1 & HIPAA §164.312(e)(1)",
                "risk_statement": "System crypto-policy permits legacy TLS 1.0 / TLS 1.1 or deprecated RC4/3DES ciphers.",
                "remediation_command": "update-crypto-policies --set DEFAULT:FEDORA32",
                "rationale": "Enforce TLS 1.2 or TLS 1.3 protocol baseline across web servers and OpenSSL configs."
            },
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": {
                "clause_id": "PCI-DSS-V4-REQ-8-3-6 / NIST-800-53-IA-5",
                "standard": "PCI-DSS v4.0.1 Req 8.3.6 & NIST 800-53 IA-5(1)",
                "risk_statement": "Password expiration parameter PASS_MAX_DAYS exceeds 90-day compliance baseline.",
                "remediation_command": "sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' {filepath}",
                "rationale": "Mandate maximum 90-day password rotation in /etc/login.defs."
            },
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": {
                "clause_id": "PCI-DSS-V4-REQ-8-2-1 / HIPAA-164-312-A1",
                "standard": "PCI-DSS v4.0.1 Req 8.2.1 & HIPAA §164.312(a)(1)",
                "risk_statement": "Default system accounts (daemon, bin, sys) have active login shells enabled.",
                "remediation_command": "usermod -s /sbin/nologin {username}",
                "rationale": "Lock non-human system accounts to prevent interactive login abuse."
            },
            "INSECURE_AUDIT_LOG_PERMISSIONS": {
                "clause_id": "HIPAA-164-312-B / PCI-DSS-V4-REQ-10-2-1",
                "standard": "HIPAA §164.312(b) & PCI-DSS v4.0.1 Req 10.2.1",
                "risk_statement": "Audit log permissions (0o666) allow unauthorized modification by non-privileged accounts.",
                "remediation_command": "chmod 600 {filepath}",
                "rationale": "Restrict audit log permissions to prevent log tampering and maintain integrity."
            }
        }

    def retrieve_context_from_db(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Similarity search inside FAISS, then relational retrieval inside SQLite database."""
        retrieved_clauses = []

        if self.ml_ready and self.model and self.index:
            try:
                query_vector = self.model.encode([query], normalize_embeddings=True)
                query_np = np.array(query_vector).astype('float32')
                distances, indices = self.index.search(query_np, top_k)

                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                coords = [int(idx) for idx in indices[0] if idx >= 0]
                if coords:
                    placeholders = ",".join("?" for _ in coords)
                    cursor.execute(f"""
                        SELECT clause_id, standard, section, context, remediation
                        FROM compliance_rules
                        WHERE id IN ({placeholders})
                    """, coords)
                    for r in cursor.fetchall():
                        retrieved_clauses.append({
                            "clause_id": r[0],
                            "standard": r[1],
                            "section": r[2],
                            "context": r[3],
                            "remediation": r[4]
                        })
                conn.close()
                if retrieved_clauses:
                    return retrieved_clauses
            except Exception as e:
                logger.debug(f"FAISS search failed: {e}")

        # Keyword-Ranked SQLite Database Search
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT clause_id, standard, section, context, remediation
                FROM compliance_rules
            """)
            all_rows = cursor.fetchall()
            conn.close()

            keywords = [k.lower() for k in query.replace("-", " ").replace("_", " ").split() if len(k) > 2]
            scored = []
            for r in all_rows:
                text_block = f"{r[0]} {r[1]} {r[2]} {r[3]} {r[4]}".lower()
                score = sum(1 for kw in keywords if kw in text_block)
                # Boost custom policy chunks and core standards
                if "custom" in text_block or "acme" in text_block:
                    score += 5
                if "hipaa" in text_block:
                    score += 2
                if "pci" in text_block:
                    score += 2
                scored.append((score, r))

            scored.sort(key=lambda x: x[0], reverse=True)
            top_rows = [r for score, r in scored[:top_k]]

            for r in top_rows:
                retrieved_clauses.append({
                    "clause_id": r[0],
                    "standard": r[1],
                    "section": r[2],
                    "context": r[3],
                    "remediation": r[4]
                })
        except Exception as e:
            logger.debug(f"SQLite search failed: {e}")

        return retrieved_clauses

    def generate_advisory(self, violation_code: str, metadata_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a structured remediation advisory card for a violation code and metadata."""
        filepath = metadata_payload.get("filepath", metadata_payload.get("file_path", "target_file"))
        query_string = f"Violation matching {violation_code} for path {filepath}"

        clauses = self.retrieve_context_from_db(query_string, top_k=3)

        fallback_item = self.fallback_dictionary.get(
            violation_code,
            self.fallback_dictionary.get(
                "ERR-OCTAL-WORLD-WRITABLE",
                {
                    "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                    "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2",
                    "risk_statement": f"Vulnerability detected ({violation_code}).",
                    "remediation_command": f"chmod 640 {filepath}",
                    "rationale": "Align file permissions and cryptographic controls with baseline security standards."
                }
            )
        )

        formatted_cmd = fallback_item["remediation_command"].format(filepath=filepath, username="system_user")

        mapped_clauses, standards_involved, contexts_retrieved = [], [], []
        for c in clauses:
            mapped_clauses.append(c['clause_id'])
            standards_involved.append(f"{c['standard']} ({c['section']})")
            contexts_retrieved.append(f"[{c['standard']} {c['section']}]: {c['context']}\nAction: {c['remediation']}")

        # Ensure fallback clause_id included if not in clauses
        fallback_cid = fallback_item["clause_id"]
        for cid_part in fallback_cid.split(" / "):
            if cid_part not in mapped_clauses:
                mapped_clauses.append(cid_part)

        remediation_card = {
            "clause_id": " / ".join(mapped_clauses),
            "standard": " | ".join(set(standards_involved)) if standards_involved else fallback_item["standard"],
            "risk_statement": fallback_item["risk_statement"],
            "remediation_command": formatted_cmd,
            "rationale": f"{fallback_item['rationale']}\n" + ("\n---\n".join(contexts_retrieved) if contexts_retrieved else ""),
            "execution_mode": "DETERMINISTIC_SINGLE_MODEL_RAG"
        }

        return remediation_card


# Alias for backward compatibility
RAGOrchestrator = RelationalRAGOrchestrator
