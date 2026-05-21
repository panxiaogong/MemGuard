"""
Task 2 — FastAPI proxy gateway (Layer 1).

Write path:
  1. SyncFilter  — PII + injection detection (blocking, sync)
  2. Sign entry  — Ed25519 provenance signature
  3. Store       — upsert to MemoryStore (InMemoryStore stub; replaced by ChromaWrapper in Task 4)
  4. Background  — ImmuneDetector (Stage 1) + ActiveImmunity if candidate (Stage 2)
                   → quarantine + memory updating if attack is confirmed

Read path:
  1. Query store
  2. Filter out is_unsafe=True entries
  3. Log each access

All gateway operations are recorded in the structured audit log.
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional, Protocol

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field

from audit.audit_log import StructuredAuditLogger
from config import settings
from db.chroma_wrapper import ChromaWrapper
from gateway.filters import SyncFilter
from gateway.immune_client import (
    ActiveImmunity,
    DualMemoryBank,
    ImmuneDetector,
)
from models.memory_entry import (
    AuditEvent,
    AuditEventType,
    KeyManager,
    MemoryEntry,
    SourceType,
)
from scanner.periodic_scanner import PeriodicScanner


# ── MemoryStore protocol (implemented by ChromaWrapper in Task 4) ─────────────


class MemoryStoreProtocol(Protocol):
    def upsert(self, entry: MemoryEntry) -> None: ...
    def get(self, entry_id: str) -> Optional[MemoryEntry]: ...
    def update_safety(self, entry_id: str, is_unsafe: bool, reason: str) -> None: ...
    def query(
        self, query_text: str, n_results: int, exclude_unsafe: bool
    ) -> list[MemoryEntry]: ...


class InMemoryStore:
    """Fallback store for unit tests that don't need a real ChromaDB server."""

    def __init__(self) -> None:
        self._entries: dict[str, MemoryEntry] = {}

    def upsert(self, entry: MemoryEntry) -> None:
        self._entries[entry.entry_id] = entry

    def get(self, entry_id: str) -> Optional[MemoryEntry]:
        return self._entries.get(entry_id)

    def update_safety(self, entry_id: str, is_unsafe: bool, reason: str) -> None:
        entry = self._entries.get(entry_id)
        if entry and is_unsafe:
            entry.quarantine(actor="immune.background", reason=reason)

    def query(
        self, query_text: str, n_results: int, exclude_unsafe: bool = True
    ) -> list[MemoryEntry]:
        entries = list(self._entries.values())
        if exclude_unsafe:
            entries = [e for e in entries if not e.is_unsafe]
        return entries[:n_results]


# ── Gateway singleton state ───────────────────────────────────────────────────


class _GatewayState:
    key_manager: KeyManager
    sync_filter: SyncFilter
    immune_detector: ImmuneDetector
    active_immunity: ActiveImmunity
    memory_bank: DualMemoryBank
    audit_logger: StructuredAuditLogger
    store: MemoryStoreProtocol
    scanner: PeriodicScanner


_state = _GatewayState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _state.key_manager = KeyManager(settings.memguard_ed25519_private_key)
    _state.sync_filter = SyncFilter()
    _state.memory_bank = DualMemoryBank()
    _state.immune_detector = ImmuneDetector(
        memory_bank=_state.memory_bank,
        model=settings.embedding_model,
        threshold=0.5,
        top_k=5,
    )
    _state.active_immunity = ActiveImmunity(model=settings.shadow_exec_model)
    _state.audit_logger = StructuredAuditLogger(Path(settings.audit_log_file))
    _state.store = ChromaWrapper.ephemeral(
        collection_name=settings.chroma_collection,
    )
    _state.scanner = PeriodicScanner(
        store=_state.store,
        immune_detector=_state.immune_detector,
        memory_bank=_state.memory_bank,
        audit_logger=_state.audit_logger,
        model=settings.shadow_exec_model,
        sample_size=settings.scan_sample_size,
    )
    # Seed dual memory banks with default attack + benign patterns
    await _state.immune_detector.seed_default_patterns()
    await _state.scanner.start(interval_minutes=settings.scan_interval_minutes)
    yield
    await _state.scanner.stop()


app = FastAPI(title="memguard Gateway", version="1.0.0", lifespan=lifespan)


# ── Request / Response schemas ────────────────────────────────────────────────


class MemoryWriteRequest(BaseModel):
    content: str
    source_id: str
    source_type: SourceType
    session_hash: str
    trust_score: float = Field(default=0.8, ge=0.0, le=1.0)


class MemoryWriteResponse(BaseModel):
    entry_id: str
    status: str          # "accepted" | "quarantined" | "blocked"
    trust_score: float
    warnings: list[str]


class MemoryReadRequest(BaseModel):
    query: str
    session_hash: str
    n_results: int = Field(default=5, ge=1, le=50)


class MemoryReadResponse(BaseModel):
    entries: list[dict[str, Any]]
    filtered_count: int   # unsafe entries silently excluded


# ── Background: IMAG Stage 1 + Stage 2 + Memory Updating ─────────────────────


async def _immune_check_and_update(entry_id: str, content: str) -> None:
    """
    IMAG closed-loop pipeline (runs as a FastAPI background task):
      Stage 1: ImmuneDetector → attack / benign / candidate
      Stage 2: ActiveImmunity → resolve candidate via dual-agent
      Stage 3: Memory Updating → add confirmed result to short-term, promote
    """
    entry = _state.store.get(entry_id)
    if entry is None:
        return

    immune_result = await _state.immune_detector.check(content)
    embedding = await _state.immune_detector.embed(content)

    if immune_result.label == "attack":
        _state.store.update_safety(entry_id, is_unsafe=True, reason="immune_detection:attack")
        _state.memory_bank.add_short_term(embedding, "attack", content)
        _state.audit_logger.log_event(
            entry,
            AuditEvent(
                event_type=AuditEventType.IMMUNE_CHECK_FLAGGED,
                actor="immune.detector",
                detail=f"sᵃ={immune_result.distance_attack:.3f} sᵇ={immune_result.distance_benign:.3f}",
                metadata={
                    "label": immune_result.label,
                    "distance_attack": immune_result.distance_attack,
                    "distance_benign": immune_result.distance_benign,
                },
            ),
        )

    elif immune_result.label == "benign":
        _state.memory_bank.add_short_term(embedding, "benign", content)
        _state.audit_logger.log_event(
            entry,
            AuditEvent(
                event_type=AuditEventType.IMMUNE_CHECK_PASSED,
                actor="immune.detector",
                detail="immune detection: benign",
                metadata={
                    "distance_attack": immune_result.distance_attack,
                    "distance_benign": immune_result.distance_benign,
                },
            ),
        )

    else:  # candidate — route to Active Immunity (Stage 2)
        active_result = await _state.active_immunity.evaluate(content)

        if active_result.is_attack:
            _state.store.update_safety(
                entry_id, is_unsafe=True, reason=f"active_immunity:{active_result.recommendation}"
            )
            _state.memory_bank.add_short_term(embedding, "attack", content)
            _state.audit_logger.log_event(
                entry,
                AuditEvent(
                    event_type=AuditEventType.SHADOW_EXEC_UNSAFE,
                    actor="immune.active_immunity",
                    detail=active_result.recommendation,
                    metadata={"prediction_label": active_result.prediction_label},
                ),
            )
        else:
            _state.memory_bank.add_short_term(embedding, "benign", content)
            _state.audit_logger.log_event(
                entry,
                AuditEvent(
                    event_type=AuditEventType.SHADOW_EXEC_SAFE,
                    actor="immune.active_immunity",
                    detail=active_result.recommendation,
                    metadata={"prediction_label": active_result.prediction_label},
                ),
            )

    # Memory Updating (Stage 3): promote short-term to long-term
    _state.memory_bank.promote_to_long_term()


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/v1/memory/write", response_model=MemoryWriteResponse)
async def write_memory(
    req: MemoryWriteRequest, background_tasks: BackgroundTasks
) -> MemoryWriteResponse:
    # 1. Sync filter: PII + injection detection
    filter_result, masked_content = _state.sync_filter.check_and_mask(req.content)

    if filter_result.blocked:
        _state.audit_logger.log_interception(
            entry_id="(pre-create)",
            source_id=req.source_id,
            action="WRITE_BLOCKED",
            reason=", ".join(filter_result.reasons),
            actor="gateway.sync_filter",
        )
        raise HTTPException(
            status_code=400,
            detail={"error": "content_blocked", "reasons": filter_result.reasons},
        )

    # 2. Create MemoryEntry with (potentially PII-masked) content
    entry = MemoryEntry(
        content=masked_content,
        source_id=req.source_id,
        source_type=req.source_type,
        session_hash=req.session_hash,
        trust_score=req.trust_score,
    )
    # Recompute content_hash after masking (hash covers masked text)
    if filter_result.pii_found:
        entry.content_hash = hashlib.sha256(masked_content.encode("utf-8")).hexdigest()

    # 3. Record filter pass
    entry.add_audit_event(
        AuditEvent(
            event_type=AuditEventType.FILTER_PASSED,
            actor="gateway.sync_filter",
            detail="sync filter passed",
            metadata={"warnings": filter_result.warnings},
        )
    )

    # 4. Sign with Ed25519
    entry.sign(_state.key_manager.private_key)

    # 5. Record creation
    entry.add_audit_event(
        AuditEvent(event_type=AuditEventType.CREATED, actor="gateway.proxy")
    )

    # 6. Store in vector DB
    _state.store.upsert(entry)
    _state.audit_logger.log_write(entry, actor="gateway.proxy")

    # 7. Schedule async IMAG pipeline (Stage 1 → 2 → 3)
    background_tasks.add_task(_immune_check_and_update, entry.entry_id, masked_content)

    return MemoryWriteResponse(
        entry_id=entry.entry_id,
        status="accepted",
        trust_score=entry.trust_score,
        warnings=filter_result.warnings,
    )


@app.post("/v1/memory/read", response_model=MemoryReadResponse)
async def read_memory(req: MemoryReadRequest) -> MemoryReadResponse:
    all_results = _state.store.query(
        req.query, n_results=req.n_results * 2, exclude_unsafe=False
    )
    safe_entries: list[MemoryEntry] = []
    filtered_count = 0

    for entry in all_results:
        if entry.is_unsafe:
            _state.audit_logger.log_read(
                entry.entry_id, actor="gateway.proxy", blocked=True, reason="is_unsafe=True"
            )
            filtered_count += 1
        else:
            _state.audit_logger.log_read(
                entry.entry_id, actor="gateway.proxy", blocked=False
            )
            safe_entries.append(entry)

    return MemoryReadResponse(
        entries=[e.to_dict() for e in safe_entries[: req.n_results]],
        filtered_count=filtered_count,
    )


@app.get("/v1/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "attack_bank_size": _state.memory_bank.attack_size,
        "benign_bank_size": _state.memory_bank.benign_size,
        "scanner_running": (
            _state.scanner._scheduler is not None
            and _state.scanner._scheduler.running
        ),
        "store": "ChromaDB",
    }
