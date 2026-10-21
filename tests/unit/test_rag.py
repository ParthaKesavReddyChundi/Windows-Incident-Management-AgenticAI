"""
tests/unit/test_rag.py
======================
Unit and integration tests for Phase 6 RAG Knowledge Base:
- Document chunking and metadata ingestion
- SentenceTransformer vector embedding and dimension validation
- ChromaDB persistent vector store indexing, querying, and filtering
- Semantic retrieval relevance and prompt context formulation
- FastAPI RAG REST endpoints
"""
from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from config.settings import settings
from rag.embedder import ChromaEmbeddingFunctionAdapter, LocalEmbedder
from rag.ingester import DocumentChunk, KnowledgeIngester
from rag.retriever import KnowledgeRetriever
from rag.vector_store import ChromaVectorStore, SearchResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def shared_embedder() -> LocalEmbedder:
    """Instantiate a single shared embedder to avoid reloading model across tests."""
    return LocalEmbedder()


@pytest.fixture
def temp_vector_store(tmp_path: Path, shared_embedder: LocalEmbedder) -> ChromaVectorStore:
    """Create an isolated test ChromaVectorStore in a temporary directory."""
    store = ChromaVectorStore(
        persist_directory=tmp_path / "test_chroma",
        collection_name="test_knowledge",
        embedder=shared_embedder,
    )
    yield store
    store.clear()


@pytest.fixture
def sample_markdown_text() -> str:
    return """# Test Guide for Windows Diagnostics

## Category: CPU Performance
**Tags:** cpu, test, diagnostic, throttling

---

### Section: High CPU Workload
When CPU usage exceeds 90%, background worker threads may be caught in an infinite loop.

#### Remediation
Throttle the process priority or terminate if unresponsive.

---

### Section: Memory Starvation
When available memory drops below 500 MB, the system begins paging aggressively to disk.

#### Remediation
Trim process working sets using SetProcessWorkingSetSize.
"""


# ── 1. Document Ingestion & Chunking Tests ────────────────────────────────────

class TestKnowledgeIngester:

    def test_parse_markdown_metadata(self, sample_markdown_text: str):
        ingester = KnowledgeIngester()
        chunks = ingester.parse_markdown(sample_markdown_text, source_file="test_doc.md")

        assert len(chunks) == 2
        chunk1 = chunks[0]
        assert chunk1.title == "Test Guide for Windows Diagnostics"
        assert chunk1.section == "High CPU Workload"
        assert chunk1.category == "cpu"
        assert "cpu" in chunk1.tags
        assert "High CPU Workload" in chunk1.content

        chunk2 = chunks[1]
        assert chunk2.section == "Memory Starvation"

    def test_chunk_to_chroma_metadata(self):
        chunk = DocumentChunk(
            chunk_id="test_chk_1",
            source_file="troubleshooting_cpu.md",
            title="CPU Guide",
            section="Runaway Worker",
            category="cpu",
            tags=["cpu", "worker"],
            content="CPU runaway diagnostic",
            metadata={"priority": 1, "is_critical": True},
        )
        meta = chunk.to_chroma_metadata()

        assert meta["source_file"] == "troubleshooting_cpu.md"
        assert meta["category"] == "cpu"
        assert meta["tags"] == "cpu, worker"
        assert meta["priority"] == 1
        assert meta["is_critical"] is True
        for val in meta.values():
            assert isinstance(val, (str, int, float, bool))

    def test_load_all_sources_directory(self):
        ingester = KnowledgeIngester()
        sources_path = settings.rag_sources_path
        assert sources_path.exists(), f"Path not found: {sources_path}"

        chunks = ingester.load_directory(sources_path)
        assert len(chunks) >= 20, f"Expected at least 20 chunks, got {len(chunks)}"

        categories = {c.category for c in chunks}
        assert "cpu" in categories
        assert "memory" in categories
        assert "disk" in categories
        assert "network" in categories
        assert "services" in categories

        # Verify all chunk IDs are unique
        chunk_ids = [c.chunk_id for c in chunks]
        assert len(chunk_ids) == len(set(chunk_ids)), "Duplicate chunk IDs found"

    def test_large_block_splitting(self):
        ingester = KnowledgeIngester(max_chunk_chars=300, chunk_overlap=50)
        long_section = "### Section: Long Section\n" + ("This is a long test paragraph explaining incident management. " * 15)
        chunks = ingester.parse_markdown(long_section, source_file="long.md")

        assert len(chunks) > 1
        for c in chunks:
            assert len(c.content) <= 350


# ── 2. Embedder Engine Tests ──────────────────────────────────────────────────

class TestLocalEmbedder:

    def test_embed_single_text(self, shared_embedder: LocalEmbedder):
        emb = shared_embedder.embed_text("Windows CPU spike detected")
        assert isinstance(emb, list)
        assert len(emb) == 384
        assert all(isinstance(x, float) for x in emb)

    def test_embed_batch(self, shared_embedder: LocalEmbedder):
        texts = [
            "High memory paging rate",
            "Disk write saturation",
            "Windows service terminated unexpectedly",
        ]
        embs = shared_embedder.embed_documents(texts)
        assert len(embs) == 3
        for e in embs:
            assert len(e) == 384

    def test_dimension_property(self, shared_embedder: LocalEmbedder):
        assert shared_embedder.dimension == 384

    def test_chroma_adapter(self, shared_embedder: LocalEmbedder):
        adapter = ChromaEmbeddingFunctionAdapter(shared_embedder)
        result = adapter(["Network anomaly outbound burst"])
        assert len(result) == 1
        assert len(result[0]) == 384


# ── 3. ChromaDB Vector Store Tests ────────────────────────────────────────────

class TestChromaVectorStore:

    def test_add_and_query_chunks(self, temp_vector_store: ChromaVectorStore):
        chunks = [
            DocumentChunk(
                chunk_id="chk_cpu_1",
                source_file="cpu.md",
                title="CPU Guide",
                section="CPU Runaway",
                category="cpu",
                tags=["cpu"],
                content="Process thread consuming 100% of CPU in an infinite loop. Use Set-Process Priority Idle.",
            ),
            DocumentChunk(
                chunk_id="chk_net_1",
                source_file="net.md",
                title="Net Guide",
                section="DDoS Attack",
                category="network",
                tags=["network", "ddos"],
                content="Massive outbound SYN flood and data exfiltration. Isolate network interface with firewall rule.",
            ),
        ]

        added = temp_vector_store.add_chunks(chunks)
        assert added == 2
        assert temp_vector_store.count() == 2

        # Query CPU topic
        results = temp_vector_store.query("infinite loop consuming high CPU", top_k=2)
        assert len(results) >= 1
        top_result = results[0]
        assert top_result.chunk_id == "chk_cpu_1"
        assert top_result.category == "cpu"
        assert top_result.similarity_score > 0.40

    def test_category_filtering(self, temp_vector_store: ChromaVectorStore):
        chunks = [
            DocumentChunk(
                chunk_id="chk_cpu",
                source_file="cpu.md",
                title="CPU",
                section="CPU Section",
                category="cpu",
                tags=["cpu"],
                content="High CPU usage and processor thread exhaustion.",
            ),
            DocumentChunk(
                chunk_id="chk_disk",
                source_file="disk.md",
                title="Disk",
                section="Disk Section",
                category="disk",
                tags=["disk"],
                content="High disk queue length and I/O thrashing.",
            ),
        ]
        temp_vector_store.add_chunks(chunks)

        # Query disk keyword but filter category="cpu"
        results = temp_vector_store.query("High disk queue length", category="cpu")
        for r in results:
            assert r.category == "cpu"

    def test_stats_and_clear(self, temp_vector_store: ChromaVectorStore):
        chunks = [
            DocumentChunk(
                chunk_id="chk_1",
                source_file="doc.md",
                title="Doc",
                section="Sec",
                category="services",
                tags=["svc"],
                content="Service failure test",
            )
        ]
        temp_vector_store.add_chunks(chunks)
        stats = temp_vector_store.get_stats()

        assert stats["total_chunks"] == 1
        assert stats["embedding_dimension"] == 384
        assert "services" in stats["categories"]

        temp_vector_store.clear()
        assert temp_vector_store.count() == 0


# ── 4. Knowledge Retriever & Incident Relevance Tests ─────────────────────────

class TestKnowledgeRetriever:

    @pytest.fixture(autouse=True)
    def setup_populated_retriever(self, temp_vector_store: ChromaVectorStore):
        ingester = KnowledgeIngester()
        chunks = ingester.load_directory(settings.rag_sources_path)
        temp_vector_store.add_chunks(chunks)
        self.retriever = KnowledgeRetriever(temp_vector_store)

    def test_semantic_retrieval_relevance(self):
        # Query 1: CPU runaway
        cpu_results = self.retriever.retrieve("high cpu utilization runaway process priority throttling", top_k=3)
        assert len(cpu_results) > 0
        top_cpu = cpu_results[0]
        assert "cpu" in top_cpu.category.lower() or "runbook" in top_cpu.category.lower()
        assert top_cpu.similarity_score > 0.40

        # Query 2: Service crash 7034
        svc_results = self.retriever.retrieve("Event ID 7034 service terminated unexpectedly crash recovery", top_k=3)
        assert len(svc_results) > 0
        top_svc = svc_results[0]
        assert top_svc.category in ("services", "event_log", "remediation_runbook")

        # Query 3: Outbound network exfiltration / DoS
        net_results = self.retriever.retrieve("abnormal outbound traffic burst data exfiltration network anomaly", top_k=3)
        assert len(net_results) > 0
        top_net = net_results[0]
        assert top_net.category in ("network", "mitre_attack", "remediation_runbook")

    def test_retrieve_incident_context(self):
        results = self.retriever.retrieve_incident_context(
            symptoms="Host CPU usage spiked to 98% with extreme thread contention",
            top_deviant_features=["cpu_percent", "System_Processor_Queue_Length"],
            top_k=3,
        )
        assert len(results) > 0
        assert any("cpu" in r.category for r in results)

    def test_format_context_for_prompt(self):
        results = self.retriever.retrieve("memory working set trimming pagefile thrashing", top_k=2)
        formatted = self.retriever.format_context_for_prompt(results, max_chars=2000)

        assert "### Knowledge Source" in formatted
        assert "- **File:**" in formatted
        assert "**Relevance Score:**" in formatted
        assert len(formatted) <= 2000


# ── 5. FastAPI RAG API Endpoints Tests ────────────────────────────────────────

class TestRAGAPIEndpoints:

    def test_rag_stats_endpoint(self):
        with TestClient(app) as client:
            resp = client.get("/api/rag/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert "collection_name" in data
            assert data["total_chunks"] >= 20
            assert data["embedding_dimension"] == 384
            assert "categories" in data

    def test_rag_query_endpoint(self):
        with TestClient(app) as client:
            payload = {
                "query": "unhandled service crash Event ID 7034",
                "top_k": 3,
                "min_score": 0.15,
            }
            resp = client.post("/api/rag/query", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["query"] == payload["query"]
            assert data["total_results"] >= 1
            assert data["retrieval_time_ms"] >= 0
            first = data["results"][0]
            assert "chunk_id" in first
            assert "similarity_score" in first
            assert "content" in first

    def test_rag_query_validation_error(self):
        with TestClient(app) as client:
            # Query too short (min length 2)
            resp = client.post("/api/rag/query", json={"query": "a"})
            assert resp.status_code == 422

    def test_rag_incident_context_endpoint(self):
        with TestClient(app) as client:
            payload = {
                "title": "Severe CPU Overload",
                "description": "Multi-core processor utilization at 99%",
                "top_deviant_features": ["cpu_percent", "thread_count"],
                "top_k": 2,
            }
            resp = client.post("/api/rag/incident-context", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert "query_formulated" in data
            assert data["total_results"] >= 1
            assert "formatted_context" in data
            assert "### Knowledge Source" in data["formatted_context"]

    def test_rag_reindex_endpoint(self):
        with TestClient(app) as client:
            resp = client.post("/api/rag/reindex?force=false")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            assert data["chunks_indexed"] >= 20
            assert data["elapsed_seconds"] >= 0
