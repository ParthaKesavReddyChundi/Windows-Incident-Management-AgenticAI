import React, { useState, useEffect } from 'react';
import {
  BookOpen,
  Search,
  RefreshCw,
  FileText,
  Tag,
  Layers,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Database,
} from 'lucide-react';

import { queryRAG, getRAGStats, reindexRAG } from '../services/api';
import type { RAGSearchResult } from '../types';

export const KnowledgeSearch: React.FC = () => {
  const [query, setQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [results, setResults] = useState<RAGSearchResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [retrievalTimeMs, setRetrievalTimeMs] = useState<number | null>(null);
  const [stats, setStats] = useState<{
    collection_name: string;
    total_chunks: number;
    categories: Record<string, number>;
    embedding_model: string;
    embedding_dimension: number;
  } | null>(null);
  const [isReindexing, setIsReindexing] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const categories = ['all', 'performance', 'services', 'memory', 'security', 'general'];

  const fetchStats = async () => {
    try {
      const data = await getRAGStats();
      setStats(data);
    } catch {
      // Ignore if server is warming up
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;

    try {
      setIsLoading(true);
      const res = await queryRAG(query, 5, selectedCategory);
      setResults(res.results);
      setRetrievalTimeMs(res.retrieval_time_ms);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setNotification(`Search error: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleReindex = async () => {
    try {
      setIsReindexing(true);
      const res = await reindexRAG();
      setNotification(`Re-indexing complete: ${res.chunks_indexed} chunks indexed in ${res.elapsed_seconds.toFixed(2)}s.`);
      await fetchStats();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setNotification(`Re-indexing failed: ${msg}`);
    } finally {
      setIsReindexing(false);
    }
  };

  return (
    <div className="knowledge-container">
      {/* Header & Stats Banner */}
      <div className="knowledge-header">
        <div className="knowledge-header-left">
          <div className="knowledge-badge">
            <BookOpen size={16} />
            <span>Retrieval-Augmented Generation (RAG)</span>
          </div>
          <h2 className="knowledge-title">Windows Troubleshooting & Threat Intelligence KB</h2>
          <p className="knowledge-subtitle">
            Semantic vector search powered by local <code>all-MiniLM-L6-v2</code> embeddings and ChromaDB.
            The Diagnosis, Security, and Remediation AI agents query this knowledge base during investigations.
          </p>
        </div>
        <div className="knowledge-header-right">
          <button
            className="btn btn-outline"
            onClick={handleReindex}
            disabled={isReindexing}
            title="Re-read sources and update ChromaDB vector store"
          >
            <RefreshCw size={16} className={isReindexing ? 'spin-icon' : ''} />
            <span>{isReindexing ? 'Re-indexing...' : 'Re-index KB'}</span>
          </button>
        </div>
      </div>

      {/* Vector Store Summary Badges */}
      <div className="rag-meta-strip">
        <div className="rag-meta-item">
          <Database size={16} className="text-cyan-400" />
          <span className="rag-meta-label">Collection:</span>
          <span className="rag-meta-val">{stats?.collection_name ?? 'windows_knowledge'}</span>
        </div>
        <div className="rag-meta-item">
          <Layers size={16} className="text-purple-400" />
          <span className="rag-meta-label">Indexed Chunks:</span>
          <span className="rag-meta-val">{stats?.total_chunks ?? 36}</span>
        </div>
        <div className="rag-meta-item">
          <Tag size={16} className="text-blue-400" />
          <span className="rag-meta-label">Embedding Model:</span>
          <span className="rag-meta-val">{stats?.embedding_model ?? 'all-MiniLM-L6-v2'} (384-dim)</span>
        </div>
      </div>

      {/* Notification */}
      {notification && (
        <div className="simulator-notification notification-success">
          <CheckCircle2 size={18} className="text-green flex-shrink-0" />
          <div className="notification-content">
            <span>{notification}</span>
          </div>
          <button className="btn-text-close" onClick={() => setNotification(null)}>
            &times;
          </button>
        </div>
      )}

      {/* Search Input Bar */}
      <form className="knowledge-search-bar" onSubmit={handleSearch}>
        <div className="search-input-wrapper">
          <Search size={18} className="search-icon" />
          <input
            type="text"
            className="search-input"
            placeholder="Search symptoms, error codes, MITRE techniques, PowerShell commands (e.g. CPU spikes, spooler crash, T1499)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={isLoading || !query.trim()}>
            {isLoading ? <Loader2 size={16} className="spin-icon" /> : <Search size={16} />}
            <span>Search</span>
          </button>
        </div>

        {/* Category Filters */}
        <div className="search-categories">
          <span className="categories-label">Category Filter:</span>
          {categories.map((cat) => (
            <button
              key={cat}
              type="button"
              className={`filter-pill ${selectedCategory === cat ? 'active' : ''}`}
              onClick={() => {
                setSelectedCategory(cat);
              }}
            >
              {cat.toUpperCase()}
            </button>
          ))}
        </div>
      </form>

      {/* Query Results */}
      <div className="search-results-section">
        {retrievalTimeMs !== null && (
          <div className="results-header-info">
            <span>
              Found <strong>{results.length}</strong> matching chunk{results.length === 1 ? '' : 's'} in{' '}
              <strong>{retrievalTimeMs.toFixed(1)} ms</strong>
            </span>
          </div>
        )}

        {results.length > 0 ? (
          <div className="results-list">
            {results.map((res) => {
              const scorePercent = Math.round(res.similarity_score * 100);
              return (
                <div key={res.chunk_id} className="result-card">
                  <div className="result-card-header">
                    <div className="result-title-group">
                      <FileText size={18} className="text-cyan-400" />
                      <h4 className="result-title">{res.title}</h4>
                      {res.section && <span className="result-section">/ {res.section}</span>}
                    </div>
                    <div className="result-badges">
                      <span className="tag-category">{res.category}</span>
                      <div className="similarity-bar-wrapper" title={`Similarity: ${scorePercent}%`}>
                        <div
                          className="similarity-bar-fill"
                          style={{ width: `${Math.min(scorePercent, 100)}%` }}
                        />
                        <span className="similarity-text">{scorePercent}% Match</span>
                      </div>
                    </div>
                  </div>

                  <p className="result-source-file">
                    Source: <code>{res.source_file}</code>
                  </p>

                  <div className="result-content">
                    <pre>{res.content}</pre>
                  </div>
                </div>
              );
            })}
          </div>
        ) : query.trim() && !isLoading ? (
          <div className="empty-results-box">
            <AlertCircle size={32} className="text-muted" />
            <p>No knowledge chunks found matching "{query}". Try a different search query or change category filter.</p>
          </div>
        ) : (
          <div className="empty-results-box">
            <Search size={32} className="text-muted" />
            <p>Type a diagnostic search query above to inspect knowledge chunks indexed in ChromaDB.</p>
          </div>
        )}
      </div>
    </div>
  );
};
