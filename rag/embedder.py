"""
Local Embedding Engine for Windows Incident Knowledge Base.

Wraps sentence-transformers (`all-MiniLM-L6-v2`) with GPU acceleration
when CUDA is available (e.g. RTX 4060) or fallback to CPU.
Provides both direct batch vector generation and ChromaDB-compatible
EmbeddingFunction integration.
"""
from __future__ import annotations

import logging
from typing import List, Optional

import torch
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings
from sentence_transformers import SentenceTransformer

from config.settings import settings

logger = logging.getLogger("rag.embedder")


class LocalEmbedder:
    """
    Local SentenceTransformer embedding model runner.
    Produces dense 384-dimensional vector embeddings for text chunks and queries.
    """

    _instance: Optional[LocalEmbedder] = None
    _model: Optional[SentenceTransformer] = None

    def __init__(
        self,
        model_name: Optional[str] = None,
        device: Optional[str] = None,
    ) -> None:
        self.model_name = model_name or settings.embedding_model

        if device:
            self.device = device
        else:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"

        self._load_model()

    def _load_model(self) -> None:
        """Instantiate the SentenceTransformer model if not already loaded."""
        if LocalEmbedder._model is None:
            logger.info(
                f"Loading embedding model '{self.model_name}' on device: {self.device}"
            )
            LocalEmbedder._model = SentenceTransformer(
                self.model_name, device=self.device
            )
            logger.info("Embedding model loaded successfully")
        self.model = LocalEmbedder._model

    @property
    def dimension(self) -> int:
        """Vector dimension of the embedding model (384 for all-MiniLM-L6-v2)."""
        return self.model.get_sentence_embedding_dimension()

    def embed_text(self, text: str) -> List[float]:
        """Generate normalized embedding vector for a single string."""
        emb = self.model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return emb.tolist()

    def embed_documents(
        self, texts: List[str], batch_size: int = 32
    ) -> List[List[float]]:
        """Generate normalized embedding vectors for a list of text strings."""
        if not texts:
            return []
        embs = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return embs.tolist()


class ChromaEmbeddingFunctionAdapter(EmbeddingFunction[Documents]):
    """
    ChromaDB compatible embedding function adapter wrapping LocalEmbedder.
    """

    def __init__(self, embedder: Optional[LocalEmbedder] = None) -> None:
        self.embedder = embedder or LocalEmbedder()

    @staticmethod
    def name() -> str:
        return "local_sentence_transformers"

    def get_config(self) -> dict:
        return {"name": self.name()}

    @classmethod
    def build_from_config(cls, config: dict) -> ChromaEmbeddingFunctionAdapter:
        return cls()

    def __call__(self, input: Documents) -> Embeddings:
        """Embed list of documents and return list of vectors."""
        return self.embedder.embed_documents(list(input))
