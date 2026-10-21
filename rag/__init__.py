"""
RAG (Retrieval-Augmented Generation) package for Windows Incident Management.
"""
from rag.embedder import ChromaEmbeddingFunctionAdapter, LocalEmbedder
from rag.ingester import DocumentChunk, KnowledgeIngester
from rag.retriever import KnowledgeRetriever
from rag.vector_store import ChromaVectorStore, SearchResult

__all__ = [
    "DocumentChunk",
    "KnowledgeIngester",
    "LocalEmbedder",
    "ChromaEmbeddingFunctionAdapter",
    "ChromaVectorStore",
    "SearchResult",
    "KnowledgeRetriever",
]
