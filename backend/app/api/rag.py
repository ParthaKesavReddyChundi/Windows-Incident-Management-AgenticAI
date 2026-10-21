"""
backend/app/api/rag.py
======================
REST API endpoints for Windows incident knowledge retrieval, semantic search,
and RAG collection maintenance.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, status

from backend.app.schemas.rag import (
    RAGIncidentContextRequest,
    RAGIncidentContextResponse,
    RAGQueryRequest,
    RAGQueryResponse,
    RAGQueryResult,
    RAGReindexResponse,
    RAGStatsResponse,
)
from backend.app.services.rag_service import RAGService

logger = logging.getLogger("api.rag")

router = APIRouter(prefix="/api/rag", tags=["RAG Knowledge Base"])


def get_rag_service() -> RAGService:
    """Dependency helper to get or initialize RAGService."""
    return RAGService.get_instance()


@router.post(
    "/query",
    response_model=RAGQueryResponse,
    summary="Semantic Search Knowledge Base",
    description="Search the indexed Windows incident runbooks, Microsoft event ID catalogs, and MITRE ATT&CK techniques.",
)
async def query_knowledge_base(payload: RAGQueryRequest) -> RAGQueryResponse:
    try:
        service = get_rag_service()
        results, elapsed_ms = service.query_knowledge(
            query=payload.query,
            top_k=payload.top_k,
            category=payload.category,
            min_score=payload.min_score,
        )

        formatted_results = [
            RAGQueryResult(
                chunk_id=r.chunk_id,
                source_file=r.source_file,
                title=r.title,
                section=r.section,
                category=r.category,
                content=r.content,
                similarity_score=r.similarity_score,
                distance=r.distance,
                metadata=r.metadata,
            )
            for r in results
        ]

        return RAGQueryResponse(
            query=payload.query,
            total_results=len(formatted_results),
            results=formatted_results,
            retrieval_time_ms=elapsed_ms,
        )
    except Exception as e:
        logger.error(f"Failed to execute knowledge search query: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Knowledge retrieval error: {str(e)}",
        )


@router.post(
    "/incident-context",
    response_model=RAGIncidentContextResponse,
    summary="Retrieve Formatted Prompt Context for Incident",
    description="Formulates an enriched query from incident symptoms and anomalous features, returning formatted markdown context with source citations.",
)
async def get_incident_context(
    payload: RAGIncidentContextRequest,
) -> RAGIncidentContextResponse:
    try:
        service = get_rag_service()
        formulated_query, results, formatted_context, elapsed_ms = (
            service.get_incident_context(
                title=payload.title,
                description=payload.description,
                top_deviant_features=payload.top_deviant_features,
                category=payload.category,
                top_k=payload.top_k,
            )
        )

        formatted_results = [
            RAGQueryResult(
                chunk_id=r.chunk_id,
                source_file=r.source_file,
                title=r.title,
                section=r.section,
                category=r.category,
                content=r.content,
                similarity_score=r.similarity_score,
                distance=r.distance,
                metadata=r.metadata,
            )
            for r in results
        ]

        return RAGIncidentContextResponse(
            query_formulated=formulated_query,
            total_results=len(formatted_results),
            results=formatted_results,
            formatted_context=formatted_context,
            retrieval_time_ms=elapsed_ms,
        )
    except Exception as e:
        logger.error(f"Failed to formulate incident context: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Incident context retrieval error: {str(e)}",
        )


@router.get(
    "/stats",
    response_model=RAGStatsResponse,
    summary="Get Knowledge Base Statistics",
    description="Returns metadata about total indexed chunks, categories breakdown, and embedding configurations.",
)
async def get_rag_stats() -> RAGStatsResponse:
    try:
        service = get_rag_service()
        stats = service.get_stats()
        return RAGStatsResponse(
            collection_name=stats["collection_name"],
            total_chunks=stats["total_chunks"],
            categories=stats["categories"],
            embedding_model=stats["embedding_model"],
            embedding_dimension=stats["embedding_dimension"],
            persist_directory=stats["persist_directory"],
        )
    except Exception as e:
        logger.error(f"Failed to fetch RAG stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Stats retrieval error: {str(e)}",
        )


@router.post(
    "/reindex",
    response_model=RAGReindexResponse,
    summary="Reindex All Knowledge Documents",
    description="Reloads and chunks all markdown files from rag/sources/ and upserts them into ChromaDB.",
)
async def reindex_knowledge_base(
    force: bool = Query(True, description="Clear existing collection before reindexing"),
) -> RAGReindexResponse:
    try:
        service = get_rag_service()
        count, elapsed_sec = service.reindex(force=force)
        return RAGReindexResponse(
            status="success",
            chunks_indexed=count,
            elapsed_seconds=elapsed_sec,
            message=f"Successfully indexed {count} knowledge chunks into ChromaDB in {elapsed_sec}s",
        )
    except Exception as e:
        logger.error(f"Failed to reindex knowledge base: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reindexing error: {str(e)}",
        )
