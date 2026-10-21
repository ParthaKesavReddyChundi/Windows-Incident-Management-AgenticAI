"""
backend/app/schemas/rag.py
==========================
Pydantic schemas for RAG knowledge base search, statistics, reindexing,
and incident context retrieval.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class KnowledgeCategory(str, Enum):
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    SERVICES = "services"
    EVENT_LOG = "event_log"
    MITRE_ATTACK = "mitre_attack"
    REMEDIATION_RUNBOOK = "remediation_runbook"
    BASELINES = "baselines"
    ALL = "all"


class RAGQueryRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Semantic search query string")
    top_k: int = Field(5, ge=1, le=20, description="Maximum number of results to return")
    category: Optional[str] = Field(None, description="Optional category filter (e.g. cpu, memory, event_log)")
    min_score: float = Field(0.15, ge=0.0, le=1.0, description="Minimum similarity score threshold")


class RAGIncidentContextRequest(BaseModel):
    incident_id: Optional[str] = Field(None, description="Incident UUID for reference")
    title: Optional[str] = Field(None, description="Incident title or symptom summary")
    description: Optional[str] = Field(None, description="Detailed incident description")
    top_deviant_features: Optional[List[str]] = Field(
        default_factory=list,
        description="Top anomalous features flagged by the Autoencoder",
    )
    category: Optional[str] = Field(None, description="Optional target category")
    top_k: int = Field(5, ge=1, le=20, description="Number of knowledge chunks to retrieve")


class RAGQueryResult(BaseModel):
    chunk_id: str
    source_file: str
    title: str
    section: str
    category: str
    content: str
    similarity_score: float
    distance: float
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class RAGQueryResponse(BaseModel):
    query: str
    total_results: int
    results: List[RAGQueryResult]
    retrieval_time_ms: float


class RAGIncidentContextResponse(BaseModel):
    query_formulated: str
    total_results: int
    results: List[RAGQueryResult]
    formatted_context: str = Field(
        ..., description="Markdown-formatted prompt context with citations ready for LLM"
    )
    retrieval_time_ms: float


class RAGStatsResponse(BaseModel):
    collection_name: str
    total_chunks: int
    categories: Dict[str, int]
    embedding_model: str
    embedding_dimension: int
    persist_directory: str


class RAGReindexResponse(BaseModel):
    status: str
    chunks_indexed: int
    elapsed_seconds: float
    message: str
