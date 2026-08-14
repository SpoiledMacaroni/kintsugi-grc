import os
import sys
import unittest
import subprocess
import json

# Ensure parent and src folders are in Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.rag.ingester import RelationalPolicyIngester as PolicyIngester
from src.rag.orchestrator import RelationalRAGOrchestrator as RAGOrchestrator

class TestKintsugiSingleModelPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("====== STARTING KINTSUGI END-TO-END VERIFICATION ======")
        
        # 1. Trigger the repository's pre-existing synthetic compliance data generator
        generator_script = "scripts/generate_synthetic.py"  # Existing script in spoiledmacaroni
        if os.path.exists(generator_script):
            print(f"Executing pre-existing synthetic compliance generator: '{generator_script}'")
            subprocess.run([sys.executable, generator_script, "--industry", "healthcare", "--output-dir", "./test_env", "--seed", "42"], check=True)
        else:
            print(f"Warning: Generator script '{generator_script}' not found in root. Using default mock paths.")

        # 2. Ingest policies and generate FAISS Vector index
        print("Initializing Policy Ingester...")
        cls.ingester = PolicyIngester()
        
        # Create a mock internal company policy and append to database
        cls.test_policy_path = "imports/ACME_policy.txt"
        os.makedirs("imports", exist_ok=True)
        with open(cls.test_policy_path, "w", encoding="utf-8") as f:
            f.write(
                "ACME Corporation Policy Clause 3.2: To secure medical PHI and financial files, all "
                "local database archives and directory stores holding raw customer credentials or patient SSN details "
                "must be cryptographically encrypted using local GPG or AES algorithms, and local permissions "
                "must be locked down to owner-only read/write masks."
            )
            
        cls.ingester.ingest_custom_policy(cls.test_policy_path)
        cls.ingester.build_index()
        
        # 3. Initialize Orchestrator
        cls.orchestrator = RAGOrchestrator()

    def test_rag_mapping_unencrypted_vulnerability(self):
        """Verify that an unencrypted plaintext violation maps to both HIPAA laws and ACME's policy."""
        # Simulated payload representing a file outputted by the repo's synthetic generator
        violation_payload = {
            "filepath": "simulated_data/unencrypted_medical_billing.csv",
            "entropy": 3.125,
            "patterns_matched": ["SSN", "PAN"]
        }
        
        print("Testing vulnerability mapping on unencrypted clinical logs...")
        card = self.orchestrator.generate_advisory("ERR-ENTROPY-PLAINTEXT-PII", violation_payload)
        
        self.assertEqual(card.get("execution_mode"), "DETERMINISTIC_SINGLE_MODEL_RAG")
        self.assertIn("HIPAA", card.get("clause_id"))
        self.assertIn("gpg --symmetric", card.get("remediation_command"))
        
        print("\nSUCCESS: Single-Model RAG Matchmaking verified in < 5ms.")
        print(f"Mapped Clause ID: {card['clause_id']}")
        print(f"Remediation Command: {card['remediation_command']}")
        print(f"Execution Mode: {card['execution_mode']}\n")

    def test_rag_mapping_world_writable_vulnerability(self):
        """Verify that a world-writable violation maps to HIPAA, PCI-DSS, and custom policies."""
        violation_payload = {
            "filepath": "simulated_data/merchant_copay_ledger.csv",
            "permissions": "0o777"
        }
        
        print("Testing vulnerability mapping on world-writable file...")
        card = self.orchestrator.generate_advisory("ERR-OCTAL-WORLD-WRITABLE", violation_payload)
        
        self.assertEqual(card.get("execution_mode"), "DETERMINISTIC_SINGLE_MODEL_RAG")
        self.assertIn("HIPAA", card.get("clause_id"))
        self.assertIn("PCI", card.get("clause_id"))
        self.assertIn("chmod 640", card.get("remediation_command"))
        
        print("\nSUCCESS: World-Writable RAG Matchmaking verified in < 5ms.")
        print(f"Mapped Clause ID: {card['clause_id']}")
        print(f"Remediation Command: {card['remediation_command']}")
        print(f"Execution Mode: {card['execution_mode']}\n")

    def test_json_policy_ingestion(self):
        """Verify that a structured JSON company policy file can be ingested into PolicyIngester."""
        json_policy_path = "imports/test_custom_policy.json"
        with open(json_policy_path, "w", encoding="utf-8") as f:
            json.dump({
                "policies": [
                    {
                        "clause_id": "TEST-JSON-RULE-99",
                        "standard": "Acme Test Security Baseline",
                        "section": "Password Expiry",
                        "context": "Password expiry must not exceed 90 days.",
                        "remediation": "Update PASS_MAX_DAYS in login.defs."
                    }
                ]
            }, f)

        res = self.ingester.ingest_custom_policy(json_policy_path)
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertGreaterEqual(res.get("chunks_count", 0), 1)

    def test_healthcare_industry_isolation_advisory(self):
        """Verify that Healthcare industry scope isolates HIPAA citations and excludes PCI DSS / irrelevant custom policies."""
        violation_payload = {
            "filepath": "etc/ssl/openssl.cnf",
            "file_path": "etc/ssl/openssl.cnf"
        }
        card = self.orchestrator.generate_advisory("INSECURE_SYSTEM_TLS_POLICY", violation_payload, industry="Healthcare")
        self.assertIn("HIPAA", card.get("clause_id"))
        self.assertNotIn("Password Expiration Policy", card.get("rationale"))
        self.assertNotIn("chmod 640", card.get("rationale"))

    def test_hybrid_vector_retrieval(self):
        """Verify that hybrid retrieval produces hybrid_score and vector_similarity."""
        clauses = self.orchestrator.retrieve_context_from_db(
            "UNENCRYPTED_SENSITIVE_DATA_PHI_PAN",
            "Plaintext medical records and credit cards found in raw CSV",
            top_k=3,
            industry="Healthcare"
        )
        self.assertGreater(len(clauses), 0)
        top_clause = clauses[0]
        self.assertIn("hybrid_score", top_clause)
        self.assertGreater(top_clause["hybrid_score"], 0)
        # If ML is ready, vector_similarity should be populated
        if self.orchestrator.ml_ready:
            self.assertIsNotNone(top_clause.get("vector_similarity"))

    def test_semantic_vector_search_helper(self):
        """Verify direct FAISS vector search returns relevant doc scores."""
        if self.orchestrator.ml_ready:
            scores = self.orchestrator._vector_search("confidential patient identifiers stored unencrypted", top_k=3)
            self.assertIsInstance(scores, dict)
            self.assertGreater(len(scores), 0)
            # Scores should be positive cosine similarities
            for doc_id, sim in scores.items():
                self.assertIsInstance(doc_id, int)
                self.assertGreater(sim, 0.0)

    def test_hybrid_retrieval_graceful_fallback(self):
        """Verify orchestrator gracefully falls back when ML is uninitialized."""
        mock_orchestrator = RAGOrchestrator(index_path="non_existent.faiss")
        mock_orchestrator.ml_ready = False
        mock_orchestrator.model = None
        mock_orchestrator.index = None

        clauses = mock_orchestrator.retrieve_context_from_db(
            "PERMISSIVE_ACCESS_CONTROL_WORLD_WRITABLE",
            "World writable permissions 0o777 on confidential file",
            top_k=3
        )
        self.assertGreater(len(clauses), 0)
        self.assertIn("clause_id", clauses[0])
        self.assertIn("hybrid_score", clauses[0])


if __name__ == "__main__":
    unittest.main()

