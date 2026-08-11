import os
import sqlite3
import faiss
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer
from src.database import DB_PATH, init_db

COMPLIANCE_KNOWLEDGE_BASE = [
    {
        "clause_id": "HIPAA-164-312-A1",
        "standard": "HIPAA Security Rule",
        "section": "Technical Safeguards §164.312(a)(1)",
        "context": "Access Control. Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights.",
        "remediation": "Restrict directory or file permissions immediately. Change owner-writable or world-writable settings using administrative commands."
    },
    {
        "clause_id": "HIPAA-164-312-A2-IV",
        "standard": "HIPAA Security Rule",
        "section": "Technical Safeguards §164.312(a)(2)(iv)",
        "context": "Encryption and Decryption. Implement a mechanism to encrypt and decrypt electronic protected health information.",
        "remediation": "Encrypt stored records. Plaintext medical details or patient identifiers must be run through a symmetric GPG encryption pipeline."
    },
    {
        "clause_id": "PCI-DSS-V4-REQ-3-5-1",
        "standard": "PCI-DSS v4.0.1",
        "section": "Requirement 3.5.1",
        "context": "Primary Account Numbers (PAN) must be rendered unreadable anywhere they are stored. Disk-level encryption alone does not satisfy this requirement if the operating system transparently decrypts the file system for authenticated processes.",
        "remediation": "Execute mathematical byte-level verification. Store data in encrypted database blocks or run GPG symmetric file encryption."
    },
    {
        "clause_id": "PCI-DSS-V4-REQ-7-2-1",
        "standard": "PCI-DSS v4.0.1",
        "section": "Requirement 7.2.1",
        "context": "Define access needs for each role and restrict access to system components and cardholder data based on the Principle of Least Privilege.",
        "remediation": "Verify GIDs/UIDs. Audit the active user directory to strip excess access permissions from non-essential service accounts."
    }
]

class RelationalPolicyIngester:
    def __init__(self, model_name="BAAI/bge-large-en-v1.5", cache_dir="./.model_cache"):
        os.makedirs(cache_dir, exist_ok=True)
        model_path = os.path.join(cache_dir, f"models--{model_name.replace('/', '--')}")
        if not os.path.exists(model_path):
            ans = input(f"Model {model_name} not found locally. Download it now? (y/n): ")
            if ans.lower() != 'y':
                print("Model download cancelled.")
                import sys
                sys.exit(1)
        self.model = SentenceTransformer(model_name, cache_folder=cache_dir)
        self.dimension = 1024  # BGE-Large-v1.5 produces 1024-dimensional dense vectors

    def ingest_custom_policy(self, file_path):
        """Reads a local company policy file, chunks it, and appends it to the knowledge base."""
        if not os.path.exists(file_path):
            print(f"Custom policy file '{file_path}' not found. Skipping.")
            return

        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()

        chunk_size = 500
        overlap = 100
        chunks = []
        start = 0

        while start < len(text):
            end = start + chunk_size
            chunks.append(text[start:end])
            start += (chunk_size - overlap)

        for i, chunk in enumerate(chunks):
            COMPLIANCE_KNOWLEDGE_BASE.append({
                "clause_id": f"CUSTOM-POLICY-CHUNK-{i}",
                "standard": "Custom Company Policy",
                "section": f"Section Chunk {i+1}",
                "context": chunk.strip(),
                "remediation": "Align local configurations to match security standards outlined in company policy."
            })
        print(f"Ingested {len(chunks)} chunks from custom company policy: '{file_path}'.")

    def build_index(self, output_index_path="imports/compliance_index.faiss", db_path=DB_PATH):
        # 1. Initialize relational schema
        init_db(db_path)
        print("Vectorizing compliance standards and policies via BGE-Large-v1.5...")
        
        corpus_texts = [f"{c['standard']} {c['section']}: {c['context']}" for c in COMPLIANCE_KNOWLEDGE_BASE]
        embeddings = self.model.encode(corpus_texts, normalize_embeddings=True, show_progress_bar=False)
        embeddings_np = np.array(embeddings).astype('float32')
        
        # 2. Build and write local FAISS index
        index = faiss.IndexFlatIP(self.dimension)
        index.add(embeddings_np)
        
        os.makedirs(os.path.dirname(output_index_path), exist_ok=True)
        faiss.write_index(index, output_index_path)
        
        # 3. Synchronize relational database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Clear old rules to prevent duplicate constraints on rebuild
        cursor.execute("DELETE FROM compliance_rules")
        
        for idx, rule in enumerate(COMPLIANCE_KNOWLEDGE_BASE):
            cursor.execute("""
                INSERT OR REPLACE INTO compliance_rules (id, clause_id, standard, section, context, remediation)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (idx, rule['clause_id'], rule['standard'], rule['section'], rule['context'], rule['remediation']))
            
        conn.commit()
        conn.close()
        print(f"FAISS index and SQLite compliance rules updated with {len(COMPLIANCE_KNOWLEDGE_BASE)} records.")
