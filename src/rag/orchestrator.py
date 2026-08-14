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
    from src.dep_check import ensure_dependencies
    ensure_dependencies(["numpy", "faiss", "sentence_transformers"])
    import faiss
    import numpy as np
    from sentence_transformers import SentenceTransformer
    HAS_ML_RAG = True
except Exception as e:
    logger.warning(f"ML RAG dependencies unavailable or failed to initialize: {e}")
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

        # Domain Rule Topic Map for precision keyword vector filtering
        self.rule_topic_keywords = {
            "INSECURE_SYSTEM_TLS_POLICY": ["tls", "ssl", "cipher", "ciphers", "protocol", "transmission", "openssl", "crypto-policy", "schannel", "rc4", "3des"],
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": ["ssh", "sshd", "protocol", "cipher", "ciphers", "blowfish", "3des", "hmac", "transmission"],
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": ["password", "expiry", "pass_max_days", "login.defs", "rotation", "credential"],
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": ["daemon", "shell", "passwd", "nologin", "account", "user", "hardening"],
            "INSECURE_AUDIT_LOG_PERMISSIONS": ["audit", "log", "audit.log", "tamper", "permissions", "0o666", "integrity"],
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": ["writable", "permissions", "0o777", "chmod", "least privilege", "access control"],
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": ["unencrypted", "cleartext", "phi", "pan", "ssn", "luhn", "gpg", "aes", "credit card"],
            "INSECURE_AES_ECB_BLOCK_PATTERN_LEAK": ["ecb", "aes", "cipher", "block", "entropy", "pattern"],
            "DECOMPRESSION_SAFETY_BOMB_TEST": ["zip", "decompression", "ratio", "bomb", "safety"]
        }

        # Fallback dictionary mapped by rule ID
        self.fallback_dictionary = {
            "ERR-OCTAL-WORLD-WRITABLE": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2",
                "risk_statement": "System file contains world-writable permissions (0o777), violating access controls.",
                "business_explanation": "Full Unrestricted Access: Permission 0o777 means any user, guest account, or process on the machine has write access to modify or delete this file. Changing to 0o640 restricts modification strictly to the file owner.",
                "remediation_command": "chmod 640 {filepath}",
                "rationale": "Restrict file permissions using owner/group boundaries."
            },
            "ERR-ENTROPY-PLAINTEXT-PII": {
                "clause_id": "HIPAA-164-312-A2-IV / PCI-DSS-V4-REQ-3-5-1",
                "standard": "HIPAA §164.312(a)(2)(iv) & PCI-DSS v4.0.1 Req 3.5.1",
                "risk_statement": "Cleartext sensitive records detected in unencrypted file payload.",
                "business_explanation": "Unencrypted Sensitive Data Exposure: Customer identifiers or medical records are stored in plain text. Encrypting with AES-256 renders data unreadable to unauthorized parties if stolen.",
                "remediation_command": "gpg --symmetric --cipher-algo AES256 {filepath}",
                "rationale": "Encrypt file using GPG/AES symmetric encryption."
            },
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2.1",
                "risk_statement": "File permissions '0o777' allow world-writable access to sensitive payloads, violating Least Privilege.",
                "business_explanation": "Full Unrestricted Public Access (0o777): Permission 0o777 means any user or process on the machine can read, edit, or delete this file. Running 'chmod 640' restricts write permissions exclusively to the owner and read access to authorized group members.",
                "remediation_command": "chmod 640 {filepath}",
                "rationale": "Restrict file permissions using owner/group boundaries per HIPAA §164.312(a)(1) and PCI-DSS Requirement 7.2.1."
            },
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN": {
                "clause_id": "HIPAA-164-312-A2-IV / PCI-DSS-V4-REQ-3-5-1",
                "standard": "HIPAA §164.312(a)(2)(iv) & PCI-DSS v4.0.1 Req 3.5.1",
                "risk_statement": "File contains unencrypted cleartext sensitive records (Luhn PAN credit cards or SSNs).",
                "business_explanation": "Cleartext Sensitive Records: File contains raw unencrypted credit card numbers or SSNs. Encrypting with GPG AES-256 protects stored data against theft or unauthorized inspection.",
                "remediation_command": "gpg --symmetric --cipher-algo AES256 {filepath}",
                "rationale": "Encrypt stored sensitive records using AES-256 with OpenSSL magic header formatting."
            },
            "INSECURE_SSH_TRANSMISSION_PROTOCOL": {
                "clause_id": "HIPAA-164-312-E1 / PCI-DSS-V4-REQ-2-2-4 / NIST-800-53-CM-6",
                "standard": "HIPAA §164.312(e)(1) & PCI-DSS v4.0.1 Req 2.2.4",
                "risk_statement": "SSH server configuration allows legacy Protocol 1 or weak ciphers (Blowfish/3DES).",
                "business_explanation": "Legacy Management Connection Risk: Remote SSH login permits Protocol 1 or weak ciphers (3DES/Blowfish), allowing eavesdroppers to intercept administrative sessions. Enforcing Protocol 2 and AES-CTR requires modern cryptographic protection.",
                "remediation_command": "sed -i 's/Protocol 1/Protocol 2/' {filepath} && systemctl restart sshd",
                "rationale": "Enforce SSH Protocol 2 and mandate strong AES/CTR cipher suites."
            },
            "INSECURE_SYSTEM_TLS_POLICY": {
                "clause_id": "HIPAA-164-312-E1 / PCI-DSS-V4-REQ-4-2-1 / NIST-800-53-SC-8",
                "standard": "HIPAA Technical Safeguards §164.312(e)(1) & PCI-DSS v4.0.1 Req 4.2.1",
                "risk_statement": "System crypto-policy permits legacy TLS 1.0 / TLS 1.1 or deprecated RC4/3DES ciphers.",
                "business_explanation": "Obsolete Network Encryption (TLS 1.0 / SECLEVEL=0): Setting TLS 1.0 or SECLEVEL=0 allows network connections to use legacy algorithms susceptible to eavesdropping. Updating to TLS 1.2+ mandates strong modern encryption across web servers and API endpoints.",
                "remediation_command": "update-crypto-policies --set DEFAULT:FEDORA32",
                "rationale": "Enforce TLS 1.2 or TLS 1.3 protocol baseline across web servers and OpenSSL configs."
            },
            "INSECURE_PASSWORD_POLICY_MAX_DAYS": {
                "clause_id": "HIPAA-164-312-A2-I / PCI-DSS-V4-REQ-8-3-6 / NIST-800-53-IA-5",
                "standard": "HIPAA §164.312(a)(2)(i) & PCI-DSS v4.0.1 Req 8.3.6",
                "risk_statement": "Password expiration parameter PASS_MAX_DAYS exceeds 90-day compliance baseline.",
                "business_explanation": "Passwords Set to Never Expire (99999 Days): PASS_MAX_DAYS allows passwords to stay valid for 273 years without changing. Changing to 90 forces users to update credentials regularly, revoking compromised or leaked passwords automatically.",
                "remediation_command": "sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' {filepath}",
                "rationale": "Mandate maximum 90-day password rotation in /etc/login.defs."
            },
            "INSECURE_SYSTEM_ACCOUNT_HARDENING": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-8-2-1 / NIST-800-53-AC-2",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 8.2.1",
                "risk_statement": "Default system accounts (daemon, bin, sys) have active login shells enabled.",
                "business_explanation": "Interactive Service Account Exposure: Non-human service accounts (daemon, bin, sys) have active command-line shells enabled. Setting shell to /sbin/nologin blocks interactive user logins while allowing background services to function normally.",
                "remediation_command": "usermod -s /sbin/nologin {username}",
                "rationale": "Lock non-human system accounts to prevent interactive login abuse."
            },
            "INSECURE_AUDIT_LOG_PERMISSIONS": {
                "clause_id": "HIPAA-164-312-B / PCI-DSS-V4-REQ-10-2-1 / NIST-800-53-AU-9",
                "standard": "HIPAA §164.312(b) & PCI-DSS v4.0.1 Req 10.2.1",
                "risk_statement": "Audit log permissions (0o666) allow unauthorized modification by non-privileged accounts.",
                "business_explanation": "Unprotected Audit Logs (0o666): Permission 0o666 allows any user on the system to edit or delete security log files, creating a risk where breach evidence can be erased. Changing to 0o600 restricts log access strictly to system administrators.",
                "remediation_command": "chmod 600 {filepath}",
                "rationale": "Restrict audit log permissions to prevent log tampering and maintain integrity."
            }
        }

    def _matches_industry(self, clause_id: str, standard: str, industry: str) -> bool:
        """Determines if a clause/standard belongs to the specified industry scope."""
        if not industry or industry == "All Industries":
            return True
            
        cid_upper = str(clause_id).upper()
        std_upper = str(standard).upper()

        if industry == "Healthcare":
            if "HIPAA" in cid_upper or "HIPAA" in std_upper or "CUSTOM" in cid_upper or "ACME" in std_upper:
                return True
            return False

        if "Merchant" in industry:
            if "PCI" in cid_upper or "PCI" in std_upper or "CUSTOM" in cid_upper or "ACME" in std_upper:
                return True
            return False

        if "Finance" in industry:
            if "NIST" in cid_upper or "NIST" in std_upper or "CUSTOM" in cid_upper or "ACME" in std_upper:
                return True
            return False

        if "Banking" in industry:
            if "PCI" in cid_upper or "NIST" in cid_upper or "PCI" in std_upper or "NIST" in std_upper or "CUSTOM" in cid_upper or "ACME" in std_upper:
                return True
            return False

        return True

    def _vector_search(self, query: str, top_k: int = 5) -> Dict[int, float]:
        """Performs dense vector similarity search using FAISS and returns a mapping of doc_id -> cosine similarity."""
        if not self.ml_ready or self.model is None or self.index is None:
            return {}
        try:
            total_docs = getattr(self.index, "ntotal", 0)
            if total_docs == 0:
                return {}
            query_emb = self.model.encode([query], normalize_embeddings=True, show_progress_bar=False)
            query_np = np.array(query_emb).astype('float32')
            k = min(max(top_k, 5), total_docs)
            distances, indices = self.index.search(query_np, k)

            scores = {}
            for dist, idx in zip(distances[0], indices[0]):
                if idx >= 0:
                    scores[int(idx)] = float(dist)
            return scores
        except Exception as e:
            logger.debug(f"FAISS vector search failed: {e}")
            return {}

    def retrieve_context_from_db(self, violation_code: str, query: str, top_k: int = 3, industry: str = "All Industries") -> List[Dict[str, Any]]:
        """Hybrid retrieval combining FAISS dense vector search and SQLite keyword/relational scoring."""
        retrieved_clauses = []
        topic_kw = self.rule_topic_keywords.get(violation_code, [violation_code.lower()])

        # 1. Semantic Vector Similarity Search (Dense Phase)
        vector_scores = {}
        if self.ml_ready:
            # Enrich query with topic keywords to improve dense vector match quality
            search_query = f"{query} {' '.join(topic_kw)}" if topic_kw else query
            vector_scores = self._vector_search(search_query, top_k=top_k * 3)

        # 2. Relational Query & Hybrid Ranking (Sparse + Dense Fusion)
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, clause_id, standard, section, context, remediation
                FROM compliance_rules
            """)
            all_rows = cursor.fetchall()
            conn.close()

            scored = []
            for r in all_rows:
                doc_id, cid, std, sec, ctx, rem = r[0], r[1], r[2], r[3], r[4], r[5]

                # Industry Scope Filter
                if not self._matches_industry(cid, std, industry):
                    continue

                text_block = f"{cid} {std} {sec} {ctx} {rem}".lower()
                topic_matches = sum(1 for kw in topic_kw if kw.lower() in text_block)
                is_custom = "custom" in text_block or "acme" in text_block

                # Dense semantic vector score (cosine similarity scaled)
                dense_sim = max(0.0, vector_scores.get(doc_id, 0.0))
                dense_score = dense_sim * 4.0 if dense_sim > 0.3 else 0.0

                # Sparse keyword score
                sparse_score = topic_matches * 3.0

                # Custom policy handling: must match topic keywords or have meaningful semantic similarity
                if is_custom and topic_matches == 0 and dense_sim < 0.45:
                    continue

                if is_custom and (topic_matches > 0 or dense_sim >= 0.45):
                    sparse_score += 2.0  # Boost relevant custom policy chunks

                if "hipaa" in text_block and industry == "Healthcare":
                    sparse_score += 2.0

                total_score = sparse_score + dense_score

                if total_score > 0:
                    scored.append((total_score, dense_sim, (cid, std, sec, ctx, rem)))

            scored.sort(key=lambda x: x[0], reverse=True)
            top_rows = [item for item in scored[:top_k]]

            for total_score, sim, r in top_rows:
                retrieved_clauses.append({
                    "clause_id": r[0],
                    "standard": r[1],
                    "section": r[2],
                    "context": r[3],
                    "remediation": r[4],
                    "hybrid_score": round(total_score, 4),
                    "vector_similarity": round(sim, 4) if sim > 0 else None
                })
        except Exception as e:
            logger.debug(f"Hybrid retrieval failed: {e}")

        return retrieved_clauses

    def generate_advisory(self, violation_code: str, metadata_payload: Dict[str, Any], industry: str = "All Industries") -> Dict[str, Any]:
        """Generates a structured remediation advisory card for a violation code, strictly scoped by industry."""
        filepath = metadata_payload.get("filepath", metadata_payload.get("file_path", "target_file"))
        query_string = f"Violation matching {violation_code} for path {filepath}"

        clauses = self.retrieve_context_from_db(violation_code, query_string, top_k=3, industry=industry)

        fallback_item = self.fallback_dictionary.get(
            violation_code,
            {
                "clause_id": "HIPAA-164-312-A1",
                "standard": "HIPAA §164.312(a)(1)",
                "risk_statement": f"Vulnerability detected ({violation_code}).",
                "remediation_command": f"chmod 640 {filepath}",
                "rationale": "Align file permissions and cryptographic controls with baseline security standards."
            }
        )

        formatted_cmd = fallback_item["remediation_command"].format(filepath=filepath, username="system_user")

        # Industry Scope Filter for fallback clause_id
        raw_cid_parts = fallback_item["clause_id"].split(" / ")
        filtered_cid_parts = [
            cid for cid in raw_cid_parts
            if self._matches_industry(cid, fallback_item["standard"], industry)
        ]
        if not filtered_cid_parts:
            filtered_cid_parts = raw_cid_parts

        mapped_clauses, standards_involved, contexts_retrieved = [], [], []
        for c in clauses:
            mapped_clauses.append(c['clause_id'])
            standards_involved.append(f"{c['standard']} ({c['section']})")
            contexts_retrieved.append(f"[{c['standard']} {c['section']}]: {c['context']}\nAction: {c['remediation']}")

        for cid in filtered_cid_parts:
            if cid not in mapped_clauses:
                mapped_clauses.append(cid)

        # Build clean standard summary string matching industry
        if industry == "Healthcare":
            std_str = "HIPAA Security Rule (45 CFR §164.312)"
        elif "Merchant" in industry:
            std_str = "PCI-DSS v4.0.1"
        elif "Finance" in industry:
            std_str = "NIST SP 800-53 Rev 5"
        elif "Banking" in industry:
            std_str = "PCI-DSS v4.0.1 | NIST 800-53"
        else:
            std_str = " | ".join(set(standards_involved)) if standards_involved else fallback_item["standard"]

        remediation_card = {
            "clause_id": " / ".join(mapped_clauses),
            "standard": std_str,
            "risk_statement": fallback_item["risk_statement"],
            "business_explanation": fallback_item.get("business_explanation", ""),
            "remediation_command": formatted_cmd,
            "rationale": f"{fallback_item['rationale']}\n" + ("\n---\n".join(contexts_retrieved) if contexts_retrieved else ""),
            "execution_mode": "DETERMINISTIC_SINGLE_MODEL_RAG"
        }

        return remediation_card


# Alias for backward compatibility
RAGOrchestrator = RelationalRAGOrchestrator
