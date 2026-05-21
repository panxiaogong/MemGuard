"""
Tests for Task 1: MemoryEntry, AuditEvent, KeyManager.

Run with:  pytest memguard/tests/test_memory_entry.py -v
"""

import hashlib

import pytest

from models.memory_entry import (
    AuditEvent,
    AuditEventType,
    KeyManager,
    MemoryEntry,
    SourceType,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def key_manager() -> KeyManager:
    return KeyManager()


@pytest.fixture
def entry() -> MemoryEntry:
    return MemoryEntry(
        content="The user's home directory is /home/alice",
        source_id="user:alice",
        source_type=SourceType.USER_INPUT,
        session_hash="abc123session",
        trust_score=0.9,
    )


# ── content_hash 派生 ─────────────────────────────────────────────────────────


def test_content_hash_is_sha256(entry: MemoryEntry) -> None:
    expected = hashlib.sha256(entry.content.encode("utf-8")).hexdigest()
    assert entry.content_hash == expected


def test_content_hash_not_recomputed_if_provided() -> None:
    fixed_hash = "a" * 64
    e = MemoryEntry(
        content="hello",
        content_hash=fixed_hash,
        source_id="s",
        source_type=SourceType.SYSTEM_GENERATED,
        session_hash="sess",
        trust_score=0.5,
    )
    assert e.content_hash == fixed_hash


# ── trust_score 范围保护 ──────────────────────────────────────────────────────


def test_trust_score_clamped_above_one() -> None:
    e = MemoryEntry(
        content="x", source_id="s", source_type=SourceType.SYSTEM_GENERATED,
        session_hash="sess", trust_score=1.5,
    )
    assert e.trust_score == 1.0


def test_trust_score_clamped_below_zero() -> None:
    e = MemoryEntry(
        content="x", source_id="s", source_type=SourceType.SYSTEM_GENERATED,
        session_hash="sess", trust_score=-0.1,
    )
    assert e.trust_score == 0.0


# ── Ed25519 签名与验签 ────────────────────────────────────────────────────────


def test_sign_and_verify(entry: MemoryEntry, key_manager: KeyManager) -> None:
    entry.sign(key_manager.private_key)
    assert entry.cryptographic_sig != ""
    assert entry.verify_signature(key_manager.public_key) is True


def test_verify_fails_without_signature(entry: MemoryEntry, key_manager: KeyManager) -> None:
    assert entry.verify_signature(key_manager.public_key) is False


def test_verify_fails_after_content_hash_tamper(entry: MemoryEntry, key_manager: KeyManager) -> None:
    entry.sign(key_manager.private_key)
    entry.content_hash = "0" * 64  # 模拟内容投毒
    assert entry.verify_signature(key_manager.public_key) is False


def test_verify_fails_after_source_id_tamper(entry: MemoryEntry, key_manager: KeyManager) -> None:
    entry.sign(key_manager.private_key)
    entry.source_id = "attacker:eve"
    assert entry.verify_signature(key_manager.public_key) is False


def test_verify_fails_with_wrong_key(entry: MemoryEntry, key_manager: KeyManager) -> None:
    entry.sign(key_manager.private_key)
    other_km = KeyManager()
    assert entry.verify_signature(other_km.public_key) is False


# ── 隔离（Quarantine）────────────────────────────────────────────────────────


def test_quarantine_sets_unsafe_flag(entry: MemoryEntry) -> None:
    assert entry.is_unsafe is False
    entry.quarantine(actor="immune.detector", reason="similarity to known jailbreak")
    assert entry.is_unsafe is True
    assert entry.quarantine_reason == "similarity to known jailbreak"


def test_quarantine_appends_audit_event(entry: MemoryEntry) -> None:
    entry.quarantine(actor="immune.detector", reason="test")
    assert len(entry.audit_trail) == 1
    assert entry.audit_trail[0].event_type == AuditEventType.QUARANTINED
    assert entry.audit_trail[0].actor == "immune.detector"


# ── 信任衰减（Trust Decay）───────────────────────────────────────────────────


def test_trust_decay_reduces_score(entry: MemoryEntry) -> None:
    original = entry.trust_score  # 0.9
    entry.apply_trust_decay(actor="scanner", decay_factor=0.5, reason="stale")
    assert entry.trust_score == pytest.approx(original * 0.5)


def test_trust_decay_does_not_go_negative(entry: MemoryEntry) -> None:
    entry.trust_score = 0.1
    entry.apply_trust_decay(actor="scanner", decay_factor=2.0, reason="extreme")
    assert entry.trust_score == 0.0


def test_trust_decay_appends_audit_event(entry: MemoryEntry) -> None:
    entry.apply_trust_decay(actor="scanner", decay_factor=0.1, reason="scheduled decay")
    ev = entry.audit_trail[-1]
    assert ev.event_type == AuditEventType.DECAY_APPLIED
    assert "old_score" in ev.metadata
    assert "new_score" in ev.metadata


# ── 审计链不可篡改 ────────────────────────────────────────────────────────────


def test_audit_trail_grows_correctly(entry: MemoryEntry) -> None:
    entry.quarantine(actor="a", reason="r1")
    entry.apply_trust_decay(actor="b", decay_factor=0.1, reason="r2")
    assert len(entry.audit_trail) == 2


def test_audit_event_is_immutable(entry: MemoryEntry) -> None:
    entry.quarantine(actor="a", reason="r")
    with pytest.raises(Exception):
        entry.audit_trail[0].actor = "hacked"  # type: ignore[misc]


# ── ChromaDB 往返序列化 ───────────────────────────────────────────────────────


def test_chroma_roundtrip(entry: MemoryEntry, key_manager: KeyManager) -> None:
    entry.sign(key_manager.private_key)
    doc = entry.to_chroma_document()
    restored = MemoryEntry.from_chroma_document(doc["document"], doc["metadata"])

    assert restored.entry_id == entry.entry_id
    assert restored.content == entry.content
    assert restored.content_hash == entry.content_hash
    assert restored.source_type == entry.source_type
    assert restored.trust_score == pytest.approx(entry.trust_score)
    assert restored.cryptographic_sig == entry.cryptographic_sig
    assert restored.verify_signature(key_manager.public_key) is True


def test_chroma_metadata_reflects_quarantine(entry: MemoryEntry) -> None:
    entry.quarantine(actor="test", reason="poisoned")
    doc = entry.to_chroma_document()
    assert doc["metadata"]["is_unsafe"] is True
    assert doc["metadata"]["quarantine_reason"] == "poisoned"


# ── KeyManager 导出与重载 ─────────────────────────────────────────────────────


def test_key_manager_export_and_reload() -> None:
    km1 = KeyManager()
    km2 = KeyManager(private_key_b64=km1.export_private_key_b64())
    assert km1.export_public_key_b64() == km2.export_public_key_b64()


def test_key_manager_cross_sign_verify() -> None:
    km = KeyManager()
    e = MemoryEntry(
        content="test cross-sign", source_id="sys",
        source_type=SourceType.SYSTEM_GENERATED,
        session_hash="s", trust_score=0.8,
    )
    e.sign(km.private_key)
    km2 = KeyManager(private_key_b64=km.export_private_key_b64())
    assert e.verify_signature(km2.public_key) is True
