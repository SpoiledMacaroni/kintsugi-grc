"""
Kintsugi-GRC RAG Pipeline Shim (Backward Compatibility)
Re-exports RAGPipelineClient from the clean modular location src.rag.pipeline.
"""

from src.rag.pipeline import RAGPipelineClient
from src.rag.orchestrator import RAGOrchestrator, RelationalRAGOrchestrator
from src.rag.ingester import PolicyIngester, RelationalPolicyIngester

__all__ = [
    "RAGPipelineClient",
    "RelationalRAGOrchestrator",
    "RAGOrchestrator",
    "RelationalPolicyIngester",
    "PolicyIngester",
]
