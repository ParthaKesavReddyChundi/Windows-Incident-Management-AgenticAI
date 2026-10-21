"""
RAG Ingestion and Chunking Module for Windows Incident Knowledge Base.

Parses curated markdown reference guides, troubleshooting runbooks,
and threat intelligence documents into semantically coherent chunks
with structured metadata for ChromaDB indexing.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import logging

logger = logging.getLogger("rag.ingester")


@dataclass
class DocumentChunk:
    """Represents a discrete semantic chunk of a knowledge base document."""

    chunk_id: str
    source_file: str
    title: str
    section: str
    category: str
    tags: List[str]
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_chroma_metadata(self) -> Dict[str, str | int | float | bool]:
        """
        Convert metadata to ChromaDB-compatible primitive types.
        ChromaDB only accepts str, int, float, bool.
        """
        tags_str = ", ".join(self.tags) if self.tags else ""
        meta: Dict[str, str | int | float | bool] = {
            "source_file": self.source_file,
            "title": self.title,
            "section": self.section,
            "category": self.category,
            "tags": tags_str,
        }
        for k, v in self.metadata.items():
            if isinstance(v, (str, int, float, bool)):
                meta[k] = v
            elif isinstance(v, list):
                meta[k] = ", ".join(str(item) for item in v)
        return meta


class KnowledgeIngester:
    """
    Parses and chunks Markdown documents from the knowledge repository.
    Splits along logical section boundaries (### Section:) while preserving
    contextual metadata (Category, Tags, Source).
    """

    def __init__(
        self,
        max_chunk_chars: int = 1500,
        chunk_overlap: int = 200,
    ) -> None:
        self.max_chunk_chars = max_chunk_chars
        self.chunk_overlap = chunk_overlap

    def load_directory(self, sources_dir: Path) -> List[DocumentChunk]:
        """
        Load and parse all markdown documents in the specified directory.
        """
        if not sources_dir.exists():
            logger.warning(f"Sources directory does not exist: {sources_dir}")
            return []

        all_chunks: List[DocumentChunk] = []
        md_files = sorted(sources_dir.glob("*.md"))

        if not md_files:
            logger.warning(f"No markdown files found in {sources_dir}")
            return []

        for md_file in md_files:
            chunks = self.load_file(md_file)
            all_chunks.extend(chunks)

        logger.info(
            f"Ingested {len(md_files)} files into {len(all_chunks)} semantic chunks"
        )
        return all_chunks

    def load_file(self, file_path: Path) -> List[DocumentChunk]:
        """
        Parse a single markdown file into DocumentChunks.
        """
        text = file_path.read_text(encoding="utf-8")
        return self.parse_markdown(text, source_file=file_path.name)

    def parse_markdown(self, text: str, source_file: str) -> List[DocumentChunk]:
        """
        Extract title, category, tags, and section chunks from markdown content.
        """
        lines = text.splitlines()
        title = source_file
        category = "general"
        tags: List[str] = []

        # 1. Extract document-level metadata from header
        for line in lines[:15]:
            line_stripped = line.strip()
            if line_stripped.startswith("# "):
                title = line_stripped.lstrip("# ").strip()
            elif line_stripped.startswith("## Category:"):
                category_match = re.search(r"## Category:\s*(.*)", line_stripped)
                if category_match:
                    category = category_match.group(1).strip()
            elif "**Tags:**" in line_stripped:
                tags_match = re.search(r"\*\*Tags:\*\*\s*(.*)", line_stripped)
                if tags_match:
                    tags = [t.strip() for t in tags_match.group(1).split(",") if t.strip()]

        # Derive a simplified category tag if needed (cpu, memory, disk, network, services, event_log, mitre, runbook)
        canonical_category = self._categorize_document(source_file, category)

        # 2. Split document into sections based on `### Section:` or `### `
        section_pattern = re.compile(r"^(###\s+(?:Section:\s*)?(.*))$", re.MULTILINE)
        matches = list(section_pattern.finditer(text))

        chunks: List[DocumentChunk] = []

        if not matches:
            # Document has no ### sections; treat whole document or paragraph splits as chunks
            chunks.extend(
                self._split_large_block(
                    content=text.strip(),
                    source_file=source_file,
                    title=title,
                    section="General",
                    category=canonical_category,
                    tags=tags,
                )
            )
            return chunks

        # Process each section
        for i, match in enumerate(matches):
            section_name = match.group(2).strip()
            start_pos = match.start()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            raw_section_text = text[start_pos:end_pos].strip()

            # Clean and split into chunks if section exceeds max_chunk_chars
            sub_chunks = self._split_large_block(
                content=raw_section_text,
                source_file=source_file,
                title=title,
                section=section_name,
                category=canonical_category,
                tags=tags,
            )
            chunks.extend(sub_chunks)

        return chunks

    def _split_large_block(
        self,
        content: str,
        source_file: str,
        title: str,
        section: str,
        category: str,
        tags: List[str],
    ) -> List[DocumentChunk]:
        """
        Split a content block if it exceeds max_chunk_chars, or return as single chunk.
        """
        if len(content) <= self.max_chunk_chars:
            chunk_id = self._generate_chunk_id(source_file, section, 0, content)
            return [
                DocumentChunk(
                    chunk_id=chunk_id,
                    source_file=source_file,
                    title=title,
                    section=section,
                    category=category,
                    tags=tags,
                    content=content,
                    metadata={"char_length": len(content)},
                )
            ]

        # Break into paragraphs
        raw_paragraphs = content.split("\n\n")
        processed_paragraphs: List[str] = []
        target_sub_len = max(50, self.max_chunk_chars - self.chunk_overlap - 4)

        for p in raw_paragraphs:
            p_clean = p.strip()
            if not p_clean:
                continue
            if len(p_clean) <= target_sub_len:
                processed_paragraphs.append(p_clean)
            else:
                # Subdivide oversized paragraph with overlap
                for start in range(0, len(p_clean), target_sub_len):
                    sub = p_clean[start : start + target_sub_len].strip()
                    if sub:
                        processed_paragraphs.append(sub)

        chunks: List[DocumentChunk] = []
        current_text = ""
        part_index = 0

        for p_stripped in processed_paragraphs:
            if not current_text:
                current_text = p_stripped
            elif len(current_text) + len(p_stripped) + 2 <= self.max_chunk_chars:
                current_text = (current_text + "\n\n" + p_stripped).strip()
            else:
                chunk_id = self._generate_chunk_id(
                    source_file, section, part_index, current_text
                )
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        source_file=source_file,
                        title=title,
                        section=f"{section} (Part {part_index + 1})",
                        category=category,
                        tags=tags,
                        content=current_text[: self.max_chunk_chars],
                        metadata={"part": part_index + 1, "char_length": len(current_text)},
                    )
                )
                part_index += 1
                overlap_snippet = (
                    current_text[-self.chunk_overlap :]
                    if len(current_text) > self.chunk_overlap
                    else ""
                )
                combined = (overlap_snippet + "\n\n" + p_stripped).strip()
                current_text = combined[: self.max_chunk_chars]

        if current_text:
            chunk_id = self._generate_chunk_id(
                source_file, section, part_index, current_text
            )
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    source_file=source_file,
                    title=title,
                    section=f"{section} (Part {part_index + 1})" if part_index > 0 else section,
                    category=category,
                    tags=tags,
                    content=current_text[: self.max_chunk_chars],
                    metadata={"part": part_index + 1, "char_length": len(current_text)},
                )
            )

        return chunks

    def _generate_chunk_id(
        self, source_file: str, section: str, part: int, content: str
    ) -> str:
        """Generate a deterministic unique hash ID for each chunk."""
        hasher = hashlib.sha256()
        hasher.update(f"{source_file}::{section}::{part}::{content[:100]}".encode("utf-8"))
        return f"chk_{hasher.hexdigest()[:16]}"

    def _categorize_document(self, source_file: str, raw_category: str) -> str:
        """Normalise category to standard taxonomy identifier."""
        combined = f"{source_file} {raw_category}".lower()
        if "cpu" in combined:
            return "cpu"
        elif "mem" in combined:
            return "memory"
        elif "disk" in combined:
            return "disk"
        elif "net" in combined:
            return "network"
        elif "service" in combined:
            return "services"
        elif "event" in combined:
            return "event_log"
        elif "mitre" in combined or "attack" in combined:
            return "mitre_attack"
        elif "runbook" in combined or "remediation" in combined:
            return "remediation_runbook"
        elif "baseline" in combined:
            return "baselines"
        return raw_category.lower().replace(" ", "_")
