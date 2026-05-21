"""
Task 4 — LanceDB wrapper with automatic memguard metadata injection.

LanceDB is a columnar vector database optimised for local/embedded deployments.
This wrapper provides the same MemoryStoreProtocol interface as ChromaWrapper
so either backend can be used without changing gateway code.

Trade-off vs ChromaDB:
  ChromaDB  — HTTP server, richer `where` filter, better for distributed setups
  LanceDB   — file-based, zero-server, great for single-node / edge deployments

Embedding strategy:
  LanceDB requires a vector column for similarity search. Since we do not want
  to call OpenAI on every write, we store a placeholder zero-vector by default.
  Pass `embedding` to upsert_with_embedding() if you have a pre-computed vector
  (e.g. from the immune detector's embed() call).
  For semantic query(), the caller should use query_with_embedding(); the plain
  query() method falls back to a metadata-based filter + limit.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import numpy as np
import pyarrow as pa

from models.memory_entry import MemoryEntry, SourceType

# Embedding dimension for placeholder vectors (matches text-embedding-3-small)
_EMBED_DIM = 1536


def _zero_vector() -> list[float]:
    return [0.0] * _EMBED_DIM


class LanceWrapper:
    """
    LanceDB-backed MemoryStore with automatic memguard metadata injection.

    All MemoryEntry fields are stored as named columns in a LanceDB table,
    enabling both vector search (when embeddings are provided) and
    metadata-based filtering (always available).
    """

    _SCHEMA = pa.schema(
        [
            pa.field("entry_id", pa.string()),
            pa.field("content", pa.string()),
            pa.field("content_hash", pa.string()),
            pa.field("source_id", pa.string()),
            pa.field("source_type", pa.string()),
            pa.field("session_hash", pa.string()),
            pa.field("timestamp", pa.string()),
            pa.field("trust_score", pa.float32()),
            pa.field("cryptographic_sig", pa.string()),
            pa.field("is_unsafe", pa.bool_()),
            pa.field("quarantine_reason", pa.string()),
            # Vector column — zero-vector placeholder if not provided
            pa.field("vector", pa.list_(pa.float32(), _EMBED_DIM)),
        ]
    )

    def __init__(
        self,
        db_path: str = ".lancedb",
        table_name: str = "agent_memory",
    ) -> None:
        import lancedb

        self._db = lancedb.connect(db_path)
        self._table_name = table_name
        if table_name not in self._db.list_tables():
            self._db.create_table(table_name, schema=self._SCHEMA)
        self._table = self._db.open_table(table_name)

    @classmethod
    def ephemeral(cls, table_name: str = "agent_memory") -> "LanceWrapper":
        """In-memory LanceDB (tmpdir) for testing."""
        import tempfile

        instance = cls.__new__(cls)
        tmp = tempfile.mkdtemp(prefix="lancedb_")
        instance.__init__(db_path=tmp, table_name=table_name)
        return instance

    # ── Serialization helpers ─────────────────────────────────────────────────

    @staticmethod
    def _entry_to_row(entry: MemoryEntry, vector: Optional[list[float]] = None) -> dict:
        return {
            "entry_id": entry.entry_id,
            "content": entry.content,
            "content_hash": entry.content_hash,
            "source_id": entry.source_id,
            "source_type": entry.source_type.value,
            "session_hash": entry.session_hash,
            "timestamp": entry.timestamp.isoformat(),
            "trust_score": float(entry.trust_score),
            "cryptographic_sig": entry.cryptographic_sig,
            "is_unsafe": entry.is_unsafe,
            "quarantine_reason": entry.quarantine_reason or "",
            "vector": vector or _zero_vector(),
        }

    @staticmethod
    def _row_to_entry(row: dict) -> MemoryEntry:
        return MemoryEntry.from_chroma_document(
            document=row["content"],
            metadata={
                "entry_id": row["entry_id"],
                "content_hash": row["content_hash"],
                "source_id": row["source_id"],
                "source_type": row["source_type"],
                "session_hash": row["session_hash"],
                "timestamp": row["timestamp"],
                "trust_score": float(row["trust_score"]),
                "cryptographic_sig": row.get("cryptographic_sig", ""),
                "is_unsafe": bool(row.get("is_unsafe", False)),
                "quarantine_reason": row.get("quarantine_reason") or None,
            },
        )

    # ── MemoryStoreProtocol ───────────────────────────────────────────────────

    def upsert(self, entry: MemoryEntry) -> None:
        """
        Store or update a MemoryEntry with a zero-vector placeholder.
        Use upsert_with_embedding() if you have a pre-computed vector.
        """
        self.upsert_with_embedding(entry, vector=None)

    def upsert_with_embedding(
        self, entry: MemoryEntry, vector: Optional[list[float]]
    ) -> None:
        """
        Store or update a MemoryEntry, injecting all provenance metadata
        and optionally a pre-computed embedding vector.
        """
        row = self._entry_to_row(entry, vector)
        # LanceDB upsert: delete existing row with same entry_id, then add
        try:
            self._table.delete(f"entry_id = '{entry.entry_id}'")
        except Exception:
            pass
        self._table.add([row])

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Fetch a single entry by ID."""
        result = (
            self._table.search()
            .where(f"entry_id = '{entry_id}'")
            .limit(1)
            .to_list()
        )
        if not result:
            return None
        return self._row_to_entry(result[0])

    def update_safety(self, entry_id: str, is_unsafe: bool, reason: str) -> None:
        """Quarantine an entry: fetch → mutate → re-upsert."""
        entry = self.get(entry_id)
        if entry is None:
            return
        if is_unsafe:
            entry.quarantine(actor="db.lance_wrapper", reason=reason)
        self.upsert(entry)

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        exclude_unsafe: bool = True,
    ) -> list[MemoryEntry]:
        """
        Metadata-filtered retrieval (no vector search).
        For vector similarity search, use query_with_embedding().
        """
        where = "is_unsafe = false" if exclude_unsafe else None
        search = self._table.search().limit(n_results)
        if where:
            search = search.where(where)
        rows = search.to_list()
        entries: list[MemoryEntry] = []
        for row in rows:
            try:
                entries.append(self._row_to_entry(row))
            except Exception:
                continue
        return entries

    def query_with_embedding(
        self,
        query_vector: list[float],
        n_results: int = 5,
        exclude_unsafe: bool = True,
    ) -> list[MemoryEntry]:
        """Vector similarity search using a pre-computed embedding."""
        where = "is_unsafe = false" if exclude_unsafe else None
        search = (
            self._table.search(np.array(query_vector, dtype=np.float32))
            .limit(n_results)
        )
        if where:
            search = search.where(where)
        rows = search.to_list()
        entries: list[MemoryEntry] = []
        for row in rows:
            try:
                entries.append(self._row_to_entry(row))
            except Exception:
                continue
        return entries

    # ── Snapshot / Rollback ───────────────────────────────────────────────────

    def create_snapshot(self, path: Path) -> int:
        """Export all entries to JSONL (same format as ChromaWrapper for portability)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = self._table.search().to_list()
        count = 0
        with path.open("w", encoding="utf-8") as f:
            for row in rows:
                record = {
                    "document": row["content"],
                    "metadata": {
                        k: v for k, v in row.items()
                        if k not in ("content", "vector")
                    },
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
        return count

    def restore_snapshot(self, path: Path) -> int:
        """Clear table and reload from JSONL snapshot."""
        try:
            self._table.delete("entry_id != '__never_match__'")
        except Exception:
            pass

        count = 0
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    meta = record["metadata"]
                    # Reconstruct MemoryEntry and re-upsert
                    entry = MemoryEntry.from_chroma_document(record["document"], meta)
                    self.upsert(entry)
                    count += 1
                except Exception:
                    continue
        return count

    # ── Helpers ───────────────────────────────────────────────────────────────

    def count(self) -> int:
        return self._table.count_rows()

    def count_unsafe(self) -> int:
        return self._table.count_rows(filter="is_unsafe = true")
