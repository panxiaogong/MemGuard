"""
Tests for Task 4 — ChromaWrapper and LanceWrapper.

All tests use ephemeral (in-memory) backends so no server is needed.
Run with: pytest memguard/tests/test_db.py -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from db.chroma_wrapper import ChromaWrapper
from db.lance_wrapper import LanceWrapper
from models.memory_entry import MemoryEntry, SourceType


# ── Shared helpers ────────────────────────────────────────────────────────────


def _make_entry(content: str = "hello world", trust_score: float = 0.9) -> MemoryEntry:
    return MemoryEntry(
        content=content,
        source_id="test:db",
        source_type=SourceType.USER_INPUT,
        session_hash="sess_db_test",
        trust_score=trust_score,
    )


# ── Parametrize over both backends ───────────────────────────────────────────


@pytest.fixture(params=["chroma", "lance"])
def store(request):
    import uuid
    unique = uuid.uuid4().hex[:10]
    if request.param == "chroma":
        return ChromaWrapper.ephemeral(collection_name=f"test_{unique}")
    else:
        return LanceWrapper.ephemeral(table_name=f"test_{unique}")


# ── Basic CRUD ────────────────────────────────────────────────────────────────


def test_upsert_and_get(store) -> None:
    entry = _make_entry("test content")
    store.upsert(entry)
    fetched = store.get(entry.entry_id)
    assert fetched is not None
    assert fetched.entry_id == entry.entry_id
    assert fetched.content == "test content"


def test_get_nonexistent_returns_none(store) -> None:
    assert store.get("nonexistent_id_xyz") is None


def test_upsert_idempotent(store) -> None:
    entry = _make_entry("idempotent test")
    store.upsert(entry)
    store.upsert(entry)  # second upsert should not duplicate
    assert store.count() == 1


def test_count(store) -> None:
    assert store.count() == 0
    store.upsert(_make_entry("a"))
    store.upsert(_make_entry("b"))
    assert store.count() == 2


def test_count_unsafe(store) -> None:
    safe = _make_entry("safe")
    unsafe = _make_entry("unsafe")
    store.upsert(safe)
    store.upsert(unsafe)
    store.update_safety(unsafe.entry_id, is_unsafe=True, reason="test")
    assert store.count_unsafe() == 1


# ── update_safety ─────────────────────────────────────────────────────────────


def test_update_safety_quarantines_entry(store) -> None:
    entry = _make_entry("suspicious")
    store.upsert(entry)
    store.update_safety(entry.entry_id, is_unsafe=True, reason="test quarantine")
    fetched = store.get(entry.entry_id)
    assert fetched is not None
    assert fetched.is_unsafe is True
    assert fetched.quarantine_reason is not None


def test_update_safety_nonexistent_is_noop(store) -> None:
    store.update_safety("ghost_id", is_unsafe=True, reason="noop")  # must not raise


# ── query ─────────────────────────────────────────────────────────────────────


def test_query_excludes_unsafe_by_default(store) -> None:
    safe = _make_entry("safe memory")
    unsafe = _make_entry("unsafe memory")
    store.upsert(safe)
    store.upsert(unsafe)
    store.update_safety(unsafe.entry_id, is_unsafe=True, reason="test")

    results = store.query("", n_results=10, exclude_unsafe=True)
    ids = [e.entry_id for e in results]
    assert safe.entry_id in ids
    assert unsafe.entry_id not in ids


def test_query_include_unsafe_when_flag_false(store) -> None:
    entry = _make_entry("unsafe entry")
    store.upsert(entry)
    store.update_safety(entry.entry_id, is_unsafe=True, reason="test")

    results = store.query("", n_results=10, exclude_unsafe=False)
    ids = [e.entry_id for e in results]
    assert entry.entry_id in ids


def test_query_respects_n_results(store) -> None:
    for i in range(10):
        store.upsert(_make_entry(f"entry {i}"))
    results = store.query("", n_results=3, exclude_unsafe=True)
    assert len(results) <= 3


# ── Snapshot / Restore ────────────────────────────────────────────────────────


def test_snapshot_and_restore(store) -> None:
    entries = [_make_entry(f"memory {i}") for i in range(5)]
    for e in entries:
        store.upsert(e)

    with tempfile.TemporaryDirectory() as tmpdir:
        snap_path = Path(tmpdir) / "snap" / "snapshot.jsonl"
        exported = store.create_snapshot(snap_path)
        assert exported == 5
        assert snap_path.exists()

        # Verify JSONL format
        lines = snap_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5
        for line in lines:
            record = json.loads(line)
            assert "document" in record
            assert "metadata" in record

        # Restore into a fresh store with a unique name
        import uuid
        unique = uuid.uuid4().hex[:10]
        if isinstance(store, ChromaWrapper):
            fresh = ChromaWrapper.ephemeral(collection_name=f"restore_{unique}")
        else:
            fresh = LanceWrapper.ephemeral(table_name=f"restore_{unique}")

        restored = fresh.restore_snapshot(snap_path)
        assert restored == 5
        assert fresh.count() == 5


def test_snapshot_preserves_quarantine_status(store) -> None:
    entry = _make_entry("quarantined memory")
    store.upsert(entry)
    store.update_safety(entry.entry_id, is_unsafe=True, reason="snapshot test")

    with tempfile.TemporaryDirectory() as tmpdir:
        snap_path = Path(tmpdir) / "snapshot.jsonl"
        store.create_snapshot(snap_path)

        import uuid
        unique = uuid.uuid4().hex[:10]
        if isinstance(store, ChromaWrapper):
            fresh = ChromaWrapper.ephemeral(collection_name=f"restore_q_{unique}")
        else:
            fresh = LanceWrapper.ephemeral(table_name=f"restore_q_{unique}")

        fresh.restore_snapshot(snap_path)
        fetched = fresh.get(entry.entry_id)
        assert fetched is not None
        assert fetched.is_unsafe is True


# ── LanceWrapper-specific ─────────────────────────────────────────────────────


def test_lance_upsert_with_embedding() -> None:
    store = LanceWrapper.ephemeral()
    entry = _make_entry("vector entry")
    vector = [0.1] * 1536
    store.upsert_with_embedding(entry, vector=vector)
    fetched = store.get(entry.entry_id)
    assert fetched is not None
    assert fetched.content == "vector entry"


def test_lance_query_with_embedding() -> None:
    store = LanceWrapper.ephemeral()
    for i in range(3):
        entry = _make_entry(f"vector memory {i}")
        store.upsert_with_embedding(entry, vector=[float(i) / 10] * 1536)

    results = store.query_with_embedding([0.1] * 1536, n_results=2)
    assert len(results) <= 2


def test_lance_query_with_embedding_excludes_unsafe() -> None:
    store = LanceWrapper.ephemeral()
    safe = _make_entry("safe vector")
    unsafe = _make_entry("unsafe vector")
    store.upsert_with_embedding(safe, vector=[0.0] * 1536)
    store.upsert_with_embedding(unsafe, vector=[0.0] * 1536)
    store.update_safety(unsafe.entry_id, is_unsafe=True, reason="test")

    results = store.query_with_embedding([0.0] * 1536, n_results=10, exclude_unsafe=True)
    ids = [e.entry_id for e in results]
    assert safe.entry_id in ids
    assert unsafe.entry_id not in ids


# ── ChromaWrapper-specific ────────────────────────────────────────────────────


def test_chroma_query_with_text() -> None:
    import uuid
    store = ChromaWrapper.ephemeral(collection_name=f"test_{uuid.uuid4().hex[:10]}")
    store.upsert(_make_entry("the capital of France is Paris"))
    store.upsert(_make_entry("Python is a programming language"))

    results = store.query("France capital", n_results=1)
    assert len(results) >= 1


def test_chroma_empty_query_text_full_scan() -> None:
    import uuid
    store = ChromaWrapper.ephemeral(collection_name=f"test_{uuid.uuid4().hex[:10]}")
    for i in range(3):
        store.upsert(_make_entry(f"entry {i}"))

    # empty query_text triggers the full-collection get() fallback
    results = store.query("", n_results=10, exclude_unsafe=True)
    assert len(results) == 3
