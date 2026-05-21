"""
Structured JSON audit logger for memguard.

Every intercepted, quarantined, or state-changed MemoryEntry emits a
one-line JSON record to both stderr (via stdlib logging) and an optional
JSONL file, making the audit trail machine-readable and grep-friendly.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.memory_entry import AuditEvent, MemoryEntry

_LOGGER = logging.getLogger("memguard.audit")


def _configure_logger(log_file: Optional[Path]) -> None:
    if _LOGGER.handlers:
        return  # already configured
    fmt = logging.Formatter("%(message)s")

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    _LOGGER.addHandler(sh)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        _LOGGER.addHandler(fh)

    _LOGGER.setLevel(logging.INFO)
    _LOGGER.propagate = False


class StructuredAuditLogger:
    """
    Writes one JSON line per audit event to stderr and (optionally) a JSONL file.

    Each record contains enough context to reconstruct what happened to a
    MemoryEntry without having to load the full entry from the vector DB.
    """

    def __init__(self, log_file: Optional[Path] = None):
        _configure_logger(log_file)

    # ── Public API ────────────────────────────────────────────────────────────

    def log_event(self, entry: MemoryEntry, event: AuditEvent) -> None:
        """Emit a structured record for a state-change event on an entry."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "entry_id": entry.entry_id,
            "source_id": entry.source_id,
            "source_type": entry.source_type.value,
            "event_type": event.event_type.value,
            "actor": event.actor,
            "detail": event.detail,
            "event_metadata": event.metadata,
            "is_unsafe": entry.is_unsafe,
            "trust_score": entry.trust_score,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_interception(
        self,
        entry_id: str,
        source_id: str,
        action: str,
        reason: str,
        actor: str,
        extra: Optional[dict] = None,
    ) -> None:
        """Emit a record for a gateway-level interception (before entry is created)."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "entry_id": entry_id,
            "source_id": source_id,
            "action": action,
            "reason": reason,
            "actor": actor,
        }
        if extra:
            record.update(extra)
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_write(self, entry: MemoryEntry, actor: str) -> None:
        """Convenience: log a successful memory write operation."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "MEMORY_WRITE",
            "entry_id": entry.entry_id,
            "source_id": entry.source_id,
            "source_type": entry.source_type.value,
            "session_hash": entry.session_hash,
            "trust_score": entry.trust_score,
            "sig_present": bool(entry.cryptographic_sig),
            "actor": actor,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_read(self, entry_id: str, actor: str, blocked: bool, reason: str = "") -> None:
        """Convenience: log a memory read/retrieval attempt."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "MEMORY_READ",
            "entry_id": entry_id,
            "actor": actor,
            "blocked": blocked,
            "reason": reason,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))
