"""
Semantic Knowledge Retriever for Windows Incident Root Cause Analysis and Remediation.

Translates incident symptoms, telemetry anomalies, and forensic indicators
into optimized vector search queries, retrieves relevant runbooks and technical docs,
and formats context for LLM multi-agent prompts.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from rag.vector_store import ChromaVectorStore, SearchResult

logger = logging.getLogger("rag.retriever")


class KnowledgeRetriever:
    """
    High-level retrieval engine for incident diagnosis, threat intelligence,
    and remediation runbooks.
    """

    def __init__(self, vector_store: ChromaVectorStore) -> None:
        self.vector_store = vector_store

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        category: Optional[str] = None,
        min_score: float = 0.15,
    ) -> List[SearchResult]:
        """
        Execute semantic similarity search for a query string.
        """
        return self.vector_store.query(
            query_text=query,
            top_k=top_k,
            category=category,
            min_score=min_score,
        )

    def retrieve_incident_context(
        self,
        symptoms: str,
        top_deviant_features: Optional[List[str]] = None,
        category: Optional[str] = None,
        top_k: int = 5,
        min_score: float = 0.15,
    ) -> List[SearchResult]:
        """
        Formulate an enriched query from incident symptoms and top anomalous features.
        """
        query_parts = [symptoms.strip()]

        if top_deviant_features:
            features_text = " ".join(top_deviant_features[:5])
            query_parts.append(f"Anomalous metric indicators: {features_text}")

        enriched_query = " | ".join(query_parts)
        logger.debug(f"Executing enriched incident retrieval: '{enriched_query}'")

        return self.retrieve(
            query=enriched_query,
            top_k=top_k,
            category=category,
            min_score=min_score,
        )

    def format_context_for_prompt(
        self,
        results: List[SearchResult],
        max_chars: int = 4000,
    ) -> str:
        """
        Format retrieved search results into a clean, markdown-structured reference block
        with explicit citation metadata suitable for inclusion in LLM prompt contexts.
        """
        if not results:
            return "No relevant Windows troubleshooting knowledge found for this incident."

        sections: List[str] = []
        current_length = 0

        for i, res in enumerate(results, 1):
            header = (
                f"### Knowledge Source [{i}]: {res.title} — {res.section}\n"
                f"- **File:** `{res.source_file}`\n"
                f"- **Category:** {res.category} | **Relevance Score:** {res.similarity_score:.2f}\n"
            )
            content_snippet = res.content.strip()

            block = f"{header}\n{content_snippet}\n"

            if current_length + len(block) > max_chars and sections:
                # Truncate if we would exceed budget
                remaining_budget = max_chars - current_length - len(header) - 50
                if remaining_budget > 100:
                    truncated_content = content_snippet[:remaining_budget] + "... [truncated]"
                    sections.append(f"{header}\n{truncated_content}\n")
                break

            sections.append(block)
            current_length += len(block)

        return "\n---\n".join(sections)
