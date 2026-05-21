"""
Task 1 — MAIF-compliant MemoryEntry with Ed25519 provenance signing.

Design constraints:
  - Core provenance fields (content_hash, source_id, session_hash, timestamp,
    trust_score) are signed at creation; signature detects any post-hoc tampering.
  - Safety fields (is_unsafe, quarantine_reason, trust_score) are mutable only
    through designated methods that append an AuditEvent, maintaining the
    append-only audit trail required for the immutable audit chain.
  - KeyManager handles Ed25519 keypair generation/loading from config so the
    private key never touches application code directly.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, Field, field_validator, model_validator


# ── Enumerations ──────────────────────────────────────────────────────────────


class SourceType(str, Enum):
    USER_INPUT = "USER_INPUT"
    EXTERNAL_URL = "EXTERNAL_URL"
    SYSTEM_GENERATED = "SYSTEM_GENERATED"
    TOOL_OUTPUT = "TOOL_OUTPUT"


class AuditEventType(str, Enum):
    CREATED = "CREATED"
    FILTER_PASSED = "FILTER_PASSED"
    FILTER_BLOCKED = "FILTER_BLOCKED"
    IMMUNE_CHECK_PASSED = "IMMUNE_CHECK_PASSED"
    IMMUNE_CHECK_FLAGGED = "IMMUNE_CHECK_FLAGGED"
    SHADOW_EXEC_SAFE = "SHADOW_EXEC_SAFE"
    SHADOW_EXEC_UNSAFE = "SHADOW_EXEC_UNSAFE"
    QUARANTINED = "QUARANTINED"
    DECAY_APPLIED = "DECAY_APPLIED"
    SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    TRUST_SCORE_UPDATED = "TRUST_SCORE_UPDATED"


# ── Audit Event ───────────────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """Immutable record of a single state change on a MemoryEntry."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str  # e.g. "gateway.filter", "immune.detector", "scanner.periodic"
    detail: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}  # AuditEvents are truly immutable once created


# ── Memory Entry ──────────────────────────────────────────────────────────────


class MemoryEntry(BaseModel):
    """
    MAIF-inspired structured memory object.

    Provenance fields covered by cryptographic_sig:
      entry_id, content_hash, source_id, source_type,
      session_hash, timestamp, trust_score (at creation).

    Call .sign(private_key) immediately after construction.
    Use .verify_signature(public_key) to assert integrity.
    """

    # ── Identity ──
    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # ── Content ──
    content: str
    content_hash: str = Field(default="")

    # ── Provenance (MAIF metadata) ──
    source_id: str
    source_type: SourceType
    session_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trust_score: float = Field(default=0.8)

    # ── Cryptographic provenance signature ──
    cryptographic_sig: str = Field(default="")

    # ── Mutable safety fields (written only via quarantine() / apply_trust_decay()) ──
    is_unsafe: bool = False
    quarantine_reason: Optional[str] = None

    # ── Append-only audit trail ──
    audit_trail: list[AuditEvent] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    # ── Validators ────────────────────────────────────────────────────────────

    @field_validator("trust_score")
    @classmethod
    def clamp_trust_score(cls, v: float) -> float:
        return max(0.0, min(1.0, v))

    @model_validator(mode="after")
    def _derive_content_hash(self) -> "MemoryEntry":
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                self.content.encode("utf-8")
            ).hexdigest()
        return self

    # ── Signing / Verification ────────────────────────────────────────────────

    def _signable_payload(self) -> bytes:
        """Canonical JSON bytes covering all immutable provenance fields."""
        payload = {
            "entry_id": self.entry_id,
            "content_hash": self.content_hash,
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "session_hash": self.session_hash,
            "timestamp": self.timestamp.isoformat(),
            "trust_score_at_creation": round(self.trust_score, 6),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, private_key: Ed25519PrivateKey) -> "MemoryEntry":
        """Sign the provenance payload and store the base64 signature."""
        sig_bytes = private_key.sign(self._signable_payload())
        self.cryptographic_sig = base64.b64encode(sig_bytes).decode("ascii")
        return self

    def verify_signature(self, public_key: Ed25519PublicKey) -> bool:
        """Return True if the stored signature matches the current payload."""
        if not self.cryptographic_sig:
            return False
        try:
            sig_bytes = base64.b64decode(self.cryptographic_sig)
            public_key.verify(sig_bytes, self._signable_payload())
            return True
        except (InvalidSignature, Exception):
            return False

    # ── Audit-chain mutation methods ──────────────────────────────────────────

    def add_audit_event(self, event: AuditEvent) -> None:
        """Append an audit event. This is the only sanctioned way to extend the trail."""
        self.audit_trail.append(event)

    def quarantine(self, actor: str, reason: str) -> None:
        """Mark unsafe and append a QUARANTINED audit event."""
        self.is_unsafe = True
        self.quarantine_reason = reason
        self.add_audit_event(
            AuditEvent(
                event_type=AuditEventType.QUARANTINED,
                actor=actor,
                detail=reason,
            )
        )

    def apply_trust_decay(
        self, actor: str, decay_factor: float, reason: str
    ) -> None:
        """
        Reduce trust_score by decay_factor and log the change.
        new_score = old_score * (1 - decay_factor), clamped to [0, 1].
        """
        old_score = self.trust_score
        self.trust_score = max(0.0, self.trust_score * (1.0 - decay_factor))
        self.add_audit_event(
            AuditEvent(
                event_type=AuditEventType.DECAY_APPLIED,
                actor=actor,
                detail=reason,
                metadata={"old_score": old_score, "new_score": self.trust_score},
            )
        )

    def update_trust_score(self, actor: str, new_score: float, reason: str) -> None:
        """Directly set a new trust score and log the change."""
        old_score = self.trust_score
        self.trust_score = max(0.0, min(1.0, new_score))
        self.add_audit_event(
            AuditEvent(
                event_type=AuditEventType.TRUST_SCORE_UPDATED,
                actor=actor,
                detail=reason,
                metadata={"old_score": old_score, "new_score": self.trust_score},
            )
        )

    # ── ChromaDB serialization ────────────────────────────────────────────────

    def to_chroma_document(self) -> dict[str, Any]:
        """
        Serialize for ChromaDB upsert.
        Returns a dict with keys: id, document, metadata.
        ChromaDB metadata values must be str | int | float | bool.
        """
        return {
            "id": self.entry_id,
            "document": self.content,
            "metadata": {
                "entry_id": self.entry_id,
                "content_hash": self.content_hash,
                "source_id": self.source_id,
                "source_type": self.source_type.value,
                "session_hash": self.session_hash,
                "timestamp": self.timestamp.isoformat(),
                "trust_score": self.trust_score,
                "cryptographic_sig": self.cryptographic_sig,
                "is_unsafe": self.is_unsafe,
                "quarantine_reason": self.quarantine_reason or "",
            },
        }

    @classmethod
    def from_chroma_document(cls, document: str, metadata: dict[str, Any]) -> "MemoryEntry":
        """Reconstruct a MemoryEntry from a ChromaDB query result row."""
        return cls(
            entry_id=metadata["entry_id"],
            content=document,
            content_hash=metadata["content_hash"],
            source_id=metadata["source_id"],
            source_type=SourceType(metadata["source_type"]),
            session_hash=metadata["session_hash"],
            timestamp=datetime.fromisoformat(metadata["timestamp"]),
            trust_score=float(metadata["trust_score"]),
            cryptographic_sig=metadata.get("cryptographic_sig", ""),
            is_unsafe=bool(metadata.get("is_unsafe", False)),
            quarantine_reason=metadata.get("quarantine_reason") or None,
        )

    def to_dict(self) -> dict[str, Any]:
        """Full serialization including audit trail (for logging / export)."""
        return self.model_dump(mode="json")


# ── Key Manager ───────────────────────────────────────────────────────────────


class KeyManager:
    """
    Load or generate an Ed25519 keypair for memguard provenance signing.

    Usage:
        km = KeyManager(private_key_b64=settings.memguard_ed25519_private_key)
        entry.sign(km.private_key)
        assert entry.verify_signature(km.public_key)
    """

    def __init__(self, private_key_b64: Optional[str] = None):
        if private_key_b64:
            raw = base64.b64decode(private_key_b64)
            self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            self._private_key = Ed25519PrivateKey.generate()
            print(
                "[memguard] No Ed25519 private key found. Generated a new one.\n"
                f"  → Set MEMGUARD_ED25519_PRIVATE_KEY={self.export_private_key_b64()} in .env"
            )
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def export_private_key_b64(self) -> str:
        raw = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(raw).decode("ascii")

    def export_public_key_b64(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")
