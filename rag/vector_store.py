"""
Vector Store Management using ChromaDB for Windows Incident Management.

Provides persistent vector indexing, semantic search, metadata filtering,
and similarity scoring over curated Windows troubleshooting runbooks,
forensic event log guides, and threat intelligence.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings

from config.settings import settings
from rag.embedder import ChromaEmbeddingFunctionAdapter, LocalEmbedder
from rag.ingester import DocumentChunk

logger = logging.getLogger("rag.vector_store")


@dataclass
class SearchResult:
    """Represents a scored knowledge base search result."""

    chunk_id: str
    source_file: str
    title: str
    section: str
    category: str
    content: str
    similarity_score: float
    distance: float
    metadata: Dict[str, Any]


class ChromaVectorStore:
    """
    Manages persistent local ChromaDB vector store collection.
    """

    def __init__(
        self,
        persist_directory: Optional[Path] = None,
        collection_name: Optional[str] = None,
        embedder: Optional[LocalEmbedder] = None,
    ) -> None:
        self.persist_directory = Path(persist_directory or settings.vector_store_path)
        self.collection_name = collection_name or settings.rag_collection_name
        self.persist_directory.mkdir(parents=True, exist_ok=True)

        self.embedder = embedder or LocalEmbedder()
        self.chroma_fn = ChromaEmbeddingFunctionAdapter(self.embedder)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=ChromaSettings(anonymized_telemetry=False),
        )

        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.chroma_fn,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            f"Initialized ChromaVectorStore at '{self.persist_directory}' "
            f"[collection='{self.collection_name}', items={self.count()}]"
        )

    def count(self) -> int:
        """Return the number of indexed chunks in the collection."""
        try:
            return self.collection.count()
        except Exception as e:
            logger.error(f"Error getting collection count: {e}")
            return 0

    def add_chunks(self, chunks: List[DocumentChunk], batch_size: int = 64) -> int:
        """
        Embed and upsert document chunks into the ChromaDB collection.
        Returns the number of chunks added/updated.
        """
        if not chunks:
            return 0

        total_added = 0
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i : i + batch_size]
            ids = [c.chunk_id for c in batch]
            documents = [c.content for c in batch]
            metadatas = [c.to_chroma_metadata() for c in batch]

            # Generate embeddings with our GPU/CPU embedder
            embeddings = self.embedder.embed_documents(documents)

            self.collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings,
            )
            total_added += len(batch)

        logger.info(f"Upserted {total_added} chunks into '{self.collection_name}'")
        return total_added

    def query(
        self,
        query_text: str,
        top_k: int = 5,
        category: Optional[str] = None,
        where: Optional[Dict[str, Any]] = None,
        min_score: float = 0.0,
    ) -> List[SearchResult]:
        """
        Perform semantic similarity search against indexed knowledge chunks.
        """
        if not query_text.strip() or self.count() == 0:
            return []

        # Construct filter clause
        filter_clause = where.copy() if where else {}
        if category and category != "all":
            filter_clause["category"] = category

        where_arg = filter_clause if filter_clause else None

        # Embed query text
        query_embedding = self.embedder.embed_text(query_text)

        # Query ChromaDB
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, self.count()),
            where=where_arg,
            include=["documents", "metadatas", "distances"],
        )

        search_results: List[SearchResult] = []
        if not results or not results.get("ids") or not results["ids"][0]:
            return []

        ids = results["ids"][0]
        docs = results["documents"][0] if results.get("documents") else []
        metas = results["metadatas"][0] if results.get("metadatas") else []
        distances = results["distances"][0] if results.get("distances") else []

        for idx, chunk_id in enumerate(ids):
            content = docs[idx] if idx < len(docs) else ""
            meta = metas[idx] if idx < len(metas) else {}
            dist = distances[idx] if idx < len(distances) else 1.0

            # For cosine distance (in [0, 2]), similarity is 1.0 - (dist / 2.0)
            # or with normalized vectors, cosine distance = 1 - cosine_similarity.
            similarity = max(0.0, min(1.0, 1.0 - dist))

            if similarity < min_score:
                continue

            search_results.append(
                SearchResult(
                    chunk_id=chunk_id,
                    source_file=str(meta.get("source_file", "unknown")),
                    title=str(meta.get("title", "")),
                    section=str(meta.get("section", "")),
                    category=str(meta.get("category", "")),
                    content=content,
                    similarity_score=round(similarity, 4),
                    distance=round(dist, 4),
                    metadata=meta,
                )
            )

        # Sort descending by similarity
        search_results.sort(key=lambda x: x.similarity_score, reverse=True)
        return search_results

    def get_stats(self) -> Dict[str, Any]:
        """
        Retrieve summary stats of the collection including item count and categories.
        """
        total_items = self.count()
        category_counts: Dict[str, int] = {}

        if total_items > 0:
            # Sample metadatas to compute category distribution
            data = self.collection.get(include=["metadatas"])
            if data and data.get("metadatas"):
                for m in data["metadatas"]:
                    cat = m.get("category", "unassigned")
                    category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "collection_name": self.collection_name,
            "total_chunks": total_items,
            "categories": category_counts,
            "embedding_model": self.embedder.model_name,
            "embedding_dimension": self.embedder.dimension,
            "persist_directory": str(self.persist_directory),
        }

    def clear(self) -> None:
        """Remove all items from the collection."""
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.chroma_fn,
                metadata={"hnsw:space": "cosine"},
            )
            logger.info(f"Cleared vector store collection '{self.collection_name}'")
        except Exception as e:
            logger.error(f"Error clearing collection: {e}")
