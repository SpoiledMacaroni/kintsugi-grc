"""
Kintsugi-GRC RAG Pipeline & Policy Vectorization Service
Integrates RelationalRAGOrchestrator, FAISS vector engine, 
SQLite compliance database (imports/kintsugi.db), and custom policy ingester.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.rag.orchestrator import RAGOrchestrator, RelationalRAGOrchestrator
from src.rag.ingester import PolicyIngester, RelationalPolicyIngester
from src.database import DB_PATH, init_db

logger = logging.getLogger("kintsugi_rag_pipeline")


class RAGPipelineClient:
    """Client interface delegating to RelationalRAGOrchestrator & RelationalPolicyIngester."""

    def __init__(self, db_path: str = DB_PATH, index_path: str = "imports/compliance_index.faiss"):
        self.db_path = db_path
        self.index_path = index_path
        self.orchestrator = None
        self.ingester = None
        self.connected = False

    def connect(self) -> bool:
        """Initializes relational DB and RAG Orchestrator instance."""
        try:
            init_db(self.db_path)
            self.orchestrator = RelationalRAGOrchestrator(index_path=self.index_path, db_path=self.db_path)
            self.ingester = RelationalPolicyIngester()
            self.connected = True
            logger.info(f"Successfully connected RAG Orchestrator to database '{self.db_path}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect RAG Orchestrator: {e}")
            self.connected = False
            return False

    def ingest_and_vectorize_policy(self, policy_path: Path) -> Dict[str, Any]:
        """Ingests a corporate policy file (JSON or TXT) and vectorizes statements against preseeded controls."""
        if not policy_path.exists():
            return {"status": "ERROR", "message": f"Policy document {policy_path.as_posix()} not found."}

        # Size safety check: max 10MB
        if policy_path.stat().st_size > 10 * 1024 * 1024:
            return {"status": "ERROR", "message": "Policy file exceeds 10MB limit. Please upload a smaller policy file."}

        try:
            if not self.ingester:
                self.ingester = RelationalPolicyIngester()

            result = self.ingester.ingest_custom_policy(str(policy_path))
            if result.get("status") == "ERROR":
                return result

            self.ingester.build_index(output_index_path=self.index_path, db_path=self.db_path)

            return {
                "status": "VECTORIZED",
                "policy_file": policy_path.name,
                "vector_count": result.get("chunks_count", 0),
                "db_path": self.db_path,
                "index_path": self.index_path,
                "execution_mode": "DETERMINISTIC_SINGLE_MODEL_RAG"
            }
        except Exception as e:
            logger.error(f"Failed to vectorize policy {policy_path.as_posix()}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def generate_advisory(self, finding: Dict[str, Any], industry: str = "All Industries") -> Dict[str, Any]:
        """Generates a full RAG advisory card (clause_id, standard, risk_statement, remediation_command, rationale)."""
        if not self.orchestrator:
            self.orchestrator = RelationalRAGOrchestrator(index_path=self.index_path, db_path=self.db_path)

        rule_id = finding.get("rule_id", "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE")
        file_path = finding.get("file_path", "target_file")
        payload = {"filepath": file_path, "file_path": file_path, "details": finding.get("details", {})}

        advisory_card = self.orchestrator.generate_advisory(rule_id, payload, industry=industry)
        return advisory_card

    def query_compliance_remediation(self, finding: Dict[str, Any], industry: str = "All Industries") -> str:
        """Helper returning string summary of RAG remediation command & rationale."""
        card = self.generate_advisory(finding, industry=industry)
        cmd = card.get("remediation_command", "chmod 640 {filepath}")
        clause = card.get("clause_id", "GRC-CONTROL")
        return f"[RAG Remediation - {clause}] Command: {cmd}"
