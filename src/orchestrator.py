import os
import sqlite3
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from src.database import DB_PATH

class RelationalRAGOrchestrator:
    def __init__(self,
                 index_path="imports/compliance_index.faiss",
                 db_path=DB_PATH,
                 model_name="BAAI/bge-large-en-v1.5",
                 cache_dir="./.model_cache"):
        self.db_path = db_path
        model_path = os.path.join(cache_dir, f"models--{model_name.replace('/', '--')}")
        if not os.path.exists(model_path):
            ans = input(f"Model {model_name} not found locally. Download it now? (y/n): ")
            if ans.lower() != 'y':
                print("Model download cancelled.")
                import sys
                sys.exit(1)
        self.model = SentenceTransformer(model_name, cache_folder=cache_dir)
        self.index = faiss.read_index(index_path)
        
        # Load static defaults dictionary (Deterministic Fallback)
        self.fallback_dictionary = {
            "ERR-OCTAL-WORLD-WRITABLE": {
                "clause_id": "HIPAA-164-312-A1 / PCI-DSS-V4-REQ-7-2-1",
                "standard": "HIPAA §164.312(a)(1) & PCI-DSS v4.0.1 Req 7.2",
                "risk_statement": "System file contains world-writable permissions (0o777), violating access controls.",
                "remediation_command": "chmod 640 {filepath}",
                "rationale": "Restrict file permissions using owner/group boundaries."
            }
        }

    def retrieve_context_from_db(self, query, top_k=2):
        """Similarity search inside FAISS, then relational retrieval inside SQLite."""
        query_vector = self.model.encode([query], normalize_embeddings=True)
        query_np = np.array(query_vector).astype('float32')
        
        distances, indices = self.index.search(query_np, top_k)
        retrieved_clauses = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build SQL safe parameters for FAISS coordinate indexes
        coords = [int(idx) for idx in indices[0]]
        placeholders = ",".join("?" for _ in coords)
        
        cursor.execute(f"""
            SELECT clause_id, standard, section, context, remediation
            FROM compliance_rules
            WHERE id IN ({placeholders})
        """, coords)
        
        rows = cursor.fetchall()
        for r in rows:
            retrieved_clauses.append({
                "clause_id": r[0],
                "standard": r[1],
                "section": r[2],
                "context": r[3],
                "remediation": r[4]
            })
            
        conn.close()
        return retrieved_clauses

    def generate_advisory(self, violation_code, metadata_payload):
        filepath = metadata_payload.get("filepath", "target_file")
        query_string = f"Violation matching {violation_code} for path {filepath}"
        
        # Retrieve context dynamically using our hybrid SQL query
        clauses = self.retrieve_context_from_db(query_string, top_k=2)
        
        fallback_item = self.fallback_dictionary.get(
            violation_code,
            self.fallback_dictionary["ERR-OCTAL-WORLD-WRITABLE"]
        )
        
        formatted_cmd = fallback_item["remediation_command"].format(filepath=filepath)
        
        mapped_clauses, standards_involved, contexts_retrieved = [], [], []
        for c in clauses:
            mapped_clauses.append(c['clause_id'])
            standards_involved.append(f"{c['standard']} ({c['section']})")
            contexts_retrieved.append(f"[{c['standard']} {c['section']}]: {c['context']}\nAction: {c['remediation']}")
            
        remediation_card = {
            "clause_id": " / ".join(mapped_clauses) if mapped_clauses else fallback_item["clause_id"],
            "standard": " | ".join(set(standards_involved)) if standards_involved else fallback_item["standard"],
            "risk_statement": fallback_item["risk_statement"],
            "remediation_command": formatted_cmd,
            "rationale": f"{fallback_item['rationale']}\nDATABASE MATCHES:\n" + "\n---\n".join(contexts_retrieved),
            "execution_mode": "DETERMINISTIC_SINGLE_MODEL_RAG"
        }
        
        return remediation_card
