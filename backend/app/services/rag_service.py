"""
backend/app/services/rag_service.py
===================================
Application service orchestrating knowledge base indexing, semantic search,
and LLM context generation for Windows Incident Management.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config.settings import settings
from rag.embedder import LocalEmbedder
from rag.ingester import KnowledgeIngester
from rag.retriever import KnowledgeRetriever
from rag.vector_store import ChromaVectorStore, SearchResult

logger = logging.getLogger("rag.service")


class RAGService:
    """
    Singleton service managing the lifecycle and query interfaces
    for the Windows incident RAG knowledge base.
    """

    _instance: Optional[RAGService] = None

    def __init__(
        self,
        vector_store_path: Optional[Path] = None,
        sources_path: Optional[Path] = None,
        collection_name: Optional[str] = None,
    ) -> None:
        self.sources_path = sources_path or settings.rag_sources_path
        self.vector_store_path = vector_store_path or settings.vector_store_path
        self.collection_name = collection_name or settings.rag_collection_name

        self.ingester = KnowledgeIngester()
        self.embedder = LocalEmbedder()
        self.vector_store = ChromaVectorStore(
            persist_directory=self.vector_store_path,
            collection_name=self.collection_name,
            embedder=self.embedder,
        )
        self.retriever = KnowledgeRetriever(self.vector_store)

    @classmethod
    def get_instance(cls) -> RAGService:
        """Access or instantiate the singleton RAGService."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def initialize(self, auto_index_if_empty: bool = True) -> None:
        """
        Verify vector store readiness. If collection is empty, automatically
        index source files from `rag/sources/`.
        """
        current_count = self.vector_store.count()
        logger.info(
            f"RAGService initialized. Collection '{self.collection_name}' "
            f"currently contains {current_count} indexed chunks"
        )
        if current_count == 0 and auto_index_if_empty:
            logger.info("Vector store is empty; triggering initial knowledge base indexing...")
            self.reindex(force=False)

    def query_knowledge(
        self,
        query: str,
        top_k: int = 5,
        category: Optional[str] = None,
        min_score: float = 0.15,
    ) -> Tuple[List[SearchResult], float]:
        """
        Search knowledge base with latency profiling.
        Returns (results, elapsed_ms).
        """
        start_time = time.perf_counter()
        results = self.retriever.retrieve(
            query=query,
            top_k=top_k,
            category=category,
            min_score=min_score,
        )
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return results, elapsed_ms

    def get_incident_context(
        self,
        title: Optional[str] = None,
        description: Optional[str] = None,
        top_deviant_features: Optional[List[str]] = None,
        category: Optional[str] = None,
        top_k: int = 5,
    ) -> Tuple[str, List[SearchResult], str, float]:
        """
        Synthesize incident symptoms and deviant features into an enriched query,
        retrieve relevant runbooks, and format context for LLM agents.
        Returns (formulated_query, results, formatted_markdown_context, elapsed_ms).
        """
        start_time = time.perf_counter()
        symptom_parts = []
        if title:
            symptom_parts.append(title.strip())
        if description and description != title:
            symptom_parts.append(description.strip())

        symptoms = " | ".join(symptom_parts) if symptom_parts else "Windows system anomaly"

        # Formulate query
        query_parts = [symptoms]
        if top_deviant_features:
            features_summary = ", ".join(top_deviant_features[:5])
            query_parts.append(f"Anomalous metric spikes: {features_summary}")
        formulated_query = " | ".join(query_parts)

        results = self.retriever.retrieve(
            query=formulated_query,
            top_k=top_k,
            category=category,
            min_score=0.10,
        )
        formatted_context = self.retriever.format_context_for_prompt(results)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return formulated_query, results, formatted_context, elapsed_ms

    def reindex(self, force: bool = True) -> Tuple[int, float]:
        """
        Ingest all markdown documents from sources_path and index into ChromaDB.
        Returns (chunks_indexed, elapsed_seconds).
        """
        start_time = time.perf_counter()
        if force:
            logger.info("Clearing existing vector store collection before reindexing...")
            self.vector_store.clear()

        logger.info(f"Loading documents from {self.sources_path}...")
        chunks = self.ingester.load_directory(self.sources_path)

        indexed_count = self.vector_store.add_chunks(chunks)
        elapsed_sec = round(time.perf_counter() - start_time, 2)

        logger.info(
            f"Reindexing complete: {indexed_count} chunks indexed in {elapsed_sec}s"
        )
        return indexed_count, elapsed_sec

    def get_stats(self) -> Dict[str, Any]:
        """Get vector store and collection statistics."""
        return self.vector_store.get_stats()
