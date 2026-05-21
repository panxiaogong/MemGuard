"""
Task 4 — ChromaDB wrapper with automatic memguard metadata injection.

Implements MemoryStoreProtocol so it drops-in as a replacement for
InMemoryStore in the gateway's lifespan without any other code changes.

Key responsibilities:
  upsert()         — auto-injects all MemoryEntry provenance metadata + signature
  query()          — semantic search with is_unsafe filter (default: exclude unsafe)
  update_safety()  — quarantine an entry in-place (fetch → mutate → re-upsert)
  create_snapshot() — export entire collection to a JSONL file (disaster recovery)
  restore_snapshot() — clear collection and reload from snapshot file

Embedding note:
  ChromaDB's default embedding function (all-MiniLM-L6-v2) is used for semantic
  search so no extra API call is needed at write time. The immune detector uses
  OpenAI embeddings for immune detection (separate concern).

Usage:
    # Production (remote ChromaDB server)
    store = ChromaWrapper(host="localhost", port=8000, collection="agent_memory")

    # Testing / local (in-memory, no server required)
    store = ChromaWrapper.ephemeral()
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings

from models.memory_entry import MemoryEntry


class ChromaWrapper:
    """
    ChromaDB-backed MemoryStore with automatic memguard metadata injection.

    All metadata fields produced by MemoryEntry.to_chroma_document() are stored
    verbatim in ChromaDB's metadata dict, making them queryable via ChromaDB's
    `where` filter API.
    """

    _WRITE_RETRIES = 3
    _RETRY_BASE_SECONDS = 0.05

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        collection_name: str = "agent_memory",
    ) -> None:
        self._client = chromadb.HttpClient(host=host, port=port)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        self._init_locks()

    @classmethod
    def ephemeral(cls, collection_name: str = "agent_memory") -> "ChromaWrapper":
        """
        Create an in-memory ChromaDB client — no server needed.
        Intended for tests and local development.
        """
        instance = cls.__new__(cls)
        instance._client = chromadb.EphemeralClient(
            settings=ChromaSettings(anonymized_telemetry=False)
        )
        instance._collection = instance._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        instance._init_locks()
        return instance

    def _init_locks(self) -> None:
        # Serialize writes for the same entry_id within this process.
        # This avoids local write races (read-modify-write interleaving).
        self._locks_guard = threading.Lock()
        self._entry_locks: dict[str, threading.RLock] = {}

    @contextmanager
    def _entry_lock(self, entry_id: str) -> Iterator[None]:
        with self._locks_guard:
            lock = self._entry_locks.get(entry_id)
            if lock is None:
                lock = threading.RLock()
                self._entry_locks[entry_id] = lock
        lock.acquire()
        try:
            yield
        finally:
            lock.release()

    # ── MemoryStoreProtocol ───────────────────────────────────────────────────

    def upsert(self, entry: MemoryEntry) -> None:
        """
        Store or update a MemoryEntry.
        Automatically injects all provenance metadata and Ed25519 signature
        from entry.to_chroma_document() — no manual metadata wiring needed.
        """
        doc = entry.to_chroma_document()
        entry_id = doc["id"]

        with self._entry_lock(entry_id):
            for attempt in range(1, self._WRITE_RETRIES + 1):
                try:
                    existing = self._collection.get(
                        ids=[entry_id],
                        include=["documents", "metadatas"],
                    )
                    existing_ids = existing.get("ids") or []

                    if not existing_ids:
                        # Prefer explicit add for new records. This avoids relying on
                        # any backend-specific upsert internals.
                        self._collection.add(
                            ids=[entry_id],
                            documents=[doc["document"]],
                            metadatas=[doc["metadata"]],
                        )
                        return

                    current_doc = (existing.get("documents") or [None])[0]
                    current_meta = (existing.get("metadatas") or [None])[0]
                    if current_doc == doc["document"] and current_meta == doc["metadata"]:
                        return  # idempotent no-op

                    self._collection.update(
                        ids=[entry_id],
                        documents=[doc["document"]],
                        metadatas=[doc["metadata"]],
                    )
                    return
                except Exception:
                    # Race-safe fallback: if another writer inserted the same ID
                    # between get() and add(), update() should succeed.
                    try:
                        self._collection.update(
                            ids=[entry_id],
                            documents=[doc["document"]],
                            metadatas=[doc["metadata"]],
                        )
                        return
                    except Exception:
                        if attempt == self._WRITE_RETRIES:
                            raise
                        time.sleep(self._RETRY_BASE_SECONDS * attempt)

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        """Fetch a single entry by ID. Returns None if not found."""
        result = self._collection.get(
            ids=[entry_id],
            include=["documents", "metadatas"],
        )
        if not result["ids"]:
            return None
        return MemoryEntry.from_chroma_document(
            document=result["documents"][0],
            metadata=result["metadatas"][0],
        )

    def update_safety(
        self, entry_id: str, is_unsafe: bool, reason: str
    ) -> None:
        """
        Quarantine an entry: fetch → apply quarantine mutation → re-upsert.
        This preserves the full audit trail in the ChromaDB metadata field.
        """
        with self._entry_lock(entry_id):
            entry = self.get(entry_id)
            if entry is None:
                return
            if is_unsafe:
                entry.quarantine(actor="db.chroma_wrapper", reason=reason)
            self.upsert(entry)

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        exclude_unsafe: bool = True,
    ) -> list[MemoryEntry]:
        """
        Semantic search over stored memories.

        If query_text is empty (e.g. from the periodic scanner's full-collection
        scan), falls back to get() to avoid ChromaDB's empty-query restriction.
        """
        where = {"is_unsafe": {"$eq": False}} if exclude_unsafe else None

        if not query_text.strip():
            # Full-collection fetch (used by PeriodicScanner)
            result = self._collection.get(
                where=where,
                include=["documents", "metadatas"],
                limit=n_results,
            )
            ids = result.get("ids", [])
            documents = result.get("documents", [])
            metadatas = result.get("metadatas", [])
        else:
            result = self._collection.query(
                query_texts=[query_text],
                n_results=min(n_results, max(1, self._collection.count())),
                where=where,
                include=["documents", "metadatas"],
            )
            ids = result.get("ids", [[]])[0]
            documents = result.get("documents", [[]])[0]
            metadatas = result.get("metadatas", [[]])[0]

        entries: list[MemoryEntry] = []
        for doc, meta in zip(documents, metadatas):
            try:
                entries.append(MemoryEntry.from_chroma_document(doc, meta))
            except Exception:
                continue  # skip malformed records rather than crashing the caller
        return entries

    # ── Snapshot / Rollback ───────────────────────────────────────────────────

    def create_snapshot(self, path: Path) -> int:
        """
        Export the entire collection to a JSONL file (one MemoryEntry per line).
        Returns the number of entries exported.

        The snapshot can be used to restore the collection to a known-safe state
        if a systematic memory poisoning attack is detected (spec §3.2).
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        result = self._collection.get(include=["documents", "metadatas"])
        documents = result.get("documents") or []
        metadatas = result.get("metadatas") or []

        count = 0
        with path.open("w", encoding="utf-8") as f:
            for doc, meta in zip(documents, metadatas):
                record = {"document": doc, "metadata": meta}
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
                count += 1
        return count

    def restore_snapshot(self, path: Path) -> int:
        """
        Clear the collection and reload from a JSONL snapshot file.
        Returns the number of entries restored.

        WARNING: This is a destructive operation — all current collection
        data is deleted. Intended only for disaster recovery.
        """
        self._collection.delete(where={"source_type": {"$ne": "__never_match__"}})

        count = 0
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    entry = MemoryEntry.from_chroma_document(
                        record["document"], record["metadata"]
                    )
                    self.upsert(entry)
                    count += 1
                except Exception:
                    continue
        return count

    # ── Helpers ───────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Return total number of entries in the collection."""
        return self._collection.count()

    def count_unsafe(self) -> int:
        """Return number of quarantined entries."""
        result = self._collection.get(
            where={"is_unsafe": {"$eq": True}},
            include=[],
        )
        return len(result.get("ids") or [])
