"""
Task 3 — Periodic scanner: Constitutional AI-based audit agent.

Runs on an APScheduler interval (default: every 5 minutes).
Each cycle:
  1. Samples SCAN_SAMPLE_SIZE entries from the MemoryStore that have not yet
     been verified by the scanner (no SHADOW_EXEC_* audit event).
  2. For each entry runs a two-stage probe:
       Stage A (fast) — regex matches against known dangerous patterns.
       Stage B (LLM)  — Constitutional AI evaluation via shadow probe + reflection.
  3. Applies the verdict:
       high risk  → quarantine + add embedding to attack bank + log
       medium     → trust_score decay (×0.5) + log
       low/pass   → add embedding to benign bank + log
  4. Emits a structured ScanReport to the audit logger.

Integration:
  The scanner is started from the gateway's lifespan (proxy.py) by calling
  scanner.start(interval_minutes). It shares the MemoryStore, DualMemoryBank,
  and StructuredAuditLogger instances with the gateway.
"""

from __future__ import annotations

import json as _json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from openai import AsyncOpenAI

from memguard.audit.audit_log import StructuredAuditLogger
from memguard.models.memory_entry import AuditEvent, AuditEventType, MemoryEntry
from memguard.scanner.constitutional import (
    CONSTITUTIONAL_EVAL_TEMPLATE,
    SAFETY_CONSTITUTION,
    SHADOW_PROBE_TEMPLATES,
    DangerMatch,
    fast_danger_check,
)

if TYPE_CHECKING:
    from memguard.gateway.immune_client import DualMemoryBank, ImmuneDetector
    from memguard.gateway.proxy import MemoryStoreProtocol


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class ProbeResult:
    entry_id: str
    is_dangerous: bool
    risk_level: Literal["high", "medium", "low"]
    triggered_principles: list[str]
    reason: str
    recommended_action: Literal["quarantine", "decay", "pass"]
    shadow_response: str
    fast_path: bool            # True if caught by regex before LLM call
    fast_matches: list[DangerMatch] = field(default_factory=list)


@dataclass
class ScanReport:
    cycle_start: datetime
    cycle_end: datetime
    total_sampled: int
    quarantined: int
    decayed: int
    passed: int
    skipped: int               # entries already verified
    results: list[ProbeResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_start": self.cycle_start.isoformat(),
            "cycle_end": self.cycle_end.isoformat(),
            "total_sampled": self.total_sampled,
            "quarantined": self.quarantined,
            "decayed": self.decayed,
            "passed": self.passed,
            "skipped": self.skipped,
        }


# ── Scanner ───────────────────────────────────────────────────────────────────


class PeriodicScanner:
    """
    Constitutional AI-based periodic memory auditor.

    Usage:
        scanner = PeriodicScanner(store, immune_detector, memory_bank, audit_logger)
        await scanner.start(interval_minutes=5)    # background loop
        report = await scanner.scan_once()         # manual trigger / testing
    """

    _DECAY_FACTOR_MEDIUM = 0.5   # trust_score *= (1 - 0.5) on medium risk

    def __init__(
        self,
        store: "MemoryStoreProtocol",
        immune_detector: "ImmuneDetector",
        memory_bank: "DualMemoryBank",
        audit_logger: StructuredAuditLogger,
        model: str = "gpt-4o-mini",
        sample_size: int = 20,
        openai_client: Optional[AsyncOpenAI] = None,
    ) -> None:
        self._store = store
        self._immune_detector = immune_detector
        self._memory_bank = memory_bank
        self._audit_logger = audit_logger
        self._model = model
        self._sample_size = sample_size
        self._client = openai_client if openai_client is not None else AsyncOpenAI()
        self._scheduler: Optional[AsyncIOScheduler] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self, interval_minutes: int = 5) -> None:
        """Start the APScheduler background loop."""
        self._scheduler = AsyncIOScheduler()
        self._scheduler.add_job(
            self.scan_once,
            trigger="interval",
            minutes=interval_minutes,
            id="memguard_periodic_scan",
            replace_existing=True,
        )
        self._scheduler.start()

    async def stop(self) -> None:
        """Gracefully stop the scheduler."""
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    # ── Main scan cycle ───────────────────────────────────────────────────────

    async def scan_once(self) -> ScanReport:
        """
        Run one full scan cycle. Safe to call manually for testing or
        on-demand re-scans.
        """
        cycle_start = datetime.now(timezone.utc)
        report = ScanReport(
            cycle_start=cycle_start,
            cycle_end=cycle_start,  # updated at end
            total_sampled=0,
            quarantined=0,
            decayed=0,
            passed=0,
            skipped=0,
        )

        candidates = self._select_candidates()
        report.total_sampled = len(candidates)

        for entry in candidates:
            if self._already_scanned(entry):
                report.skipped += 1
                continue

            probe = await self._probe_entry(entry)
            report.results.append(probe)

            await self._apply_verdict(entry, probe)

            if probe.recommended_action == "quarantine":
                report.quarantined += 1
            elif probe.recommended_action == "decay":
                report.decayed += 1
            else:
                report.passed += 1

        # Promote short-term memory entries accumulated during this cycle
        self._memory_bank.promote_to_long_term()

        report.cycle_end = datetime.now(timezone.utc)
        self._audit_logger.log_interception(
            entry_id="scan_report",
            source_id="scanner.periodic",
            action="SCAN_CYCLE_COMPLETE",
            reason=f"quarantined={report.quarantined} decayed={report.decayed} passed={report.passed}",
            actor="scanner.periodic",
            extra=report.to_dict(),
        )
        return report

    # ── Entry selection ───────────────────────────────────────────────────────

    def _select_candidates(self) -> list[MemoryEntry]:
        """
        Sample up to SCAN_SAMPLE_SIZE entries, prioritising:
          1. Entries not yet scanned (no SHADOW_EXEC_* event)
          2. Entries with the lowest trust_score (most suspicious)
        """
        all_entries = self._store.query(
            query_text="",   # full scan — ChromaWrapper will handle this
            n_results=self._sample_size * 4,
            exclude_unsafe=False,
        )
        # Sort: unscanned first, then by trust_score ascending
        all_entries.sort(key=lambda e: (self._already_scanned(e), e.trust_score))
        return all_entries[: self._sample_size]

    @staticmethod
    def _already_scanned(entry: MemoryEntry) -> bool:
        """Return True if this entry already has a scanner verdict in its audit trail."""
        scanner_events = {AuditEventType.SHADOW_EXEC_SAFE, AuditEventType.SHADOW_EXEC_UNSAFE}
        return any(ev.event_type in scanner_events for ev in entry.audit_trail)

    # ── Two-stage probe ───────────────────────────────────────────────────────

    async def _probe_entry(self, entry: MemoryEntry) -> ProbeResult:
        """
        Stage A: Fast regex danger check.
        Stage B: Shadow probe → Constitutional AI evaluation.

        If Stage A already catches a dangerous pattern, Stage B is still
        run to produce a complete ProbeResult (the recommendation is set
        to "quarantine" regardless of Stage B's output).
        """
        # Stage A — fast path (pure regex, no API call)
        fast_matches = fast_danger_check(entry.content)
        fast_hit = len(fast_matches) > 0

        # Stage B — shadow probe + Constitutional AI
        shadow_response = await self._run_shadow_probe(entry.content)
        probe_result = await self._constitutional_eval(entry.content, shadow_response)

        # If fast path caught something, override to high risk
        if fast_hit and probe_result["risk_level"] != "high":
            probe_result["risk_level"] = "high"
            probe_result["is_dangerous"] = True
            probe_result["recommended_action"] = "quarantine"
            probe_result["triggered_principles"].extend(
                [m.pattern_name for m in fast_matches]
            )
            if not probe_result["reason"]:
                probe_result["reason"] = f"Fast danger match: {fast_matches[0].pattern_name}"

        return ProbeResult(
            entry_id=entry.entry_id,
            is_dangerous=probe_result["is_dangerous"],
            risk_level=probe_result["risk_level"],
            triggered_principles=probe_result.get("triggered_principles", []),
            reason=probe_result.get("reason", ""),
            recommended_action=probe_result["recommended_action"],
            shadow_response=shadow_response,
            fast_path=fast_hit,
            fast_matches=fast_matches,
        )

    async def _run_shadow_probe(self, memory_content: str) -> str:
        """
        Inject memory_content into a randomly selected shadow probe template
        and return the LLM's response.

        The random template selection makes it harder for adversarial content
        to anticipate and defeat the probe framing.
        """
        template = random.choice(SHADOW_PROBE_TEMPLATES)
        prompt = template.format(memory_content=memory_content)
        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=512,
            temperature=0.0,
        )
        return resp.choices[0].message.content or ""

    async def _constitutional_eval(
        self, memory_content: str, shadow_response: str
    ) -> dict[str, Any]:
        """
        Ask the Constitutional AI evaluator whether the memory is dangerous.
        Returns parsed JSON dict with keys: is_dangerous, risk_level,
        triggered_principles, reason, recommended_action.
        """
        constitution_str = "\n".join(
            f"  {i+1}. {p}" for i, p in enumerate(SAFETY_CONSTITUTION)
        )
        prompt = CONSTITUTIONAL_EVAL_TEMPLATE.format(
            memory_content=memory_content,
            shadow_response=shadow_response,
            constitution=constitution_str,
        )
        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        raw = resp.choices[0].message.content or "{}"
        try:
            data = _json.loads(raw)
            return {
                "is_dangerous": bool(data.get("is_dangerous", False)),
                "risk_level": data.get("risk_level", "low"),
                "triggered_principles": data.get("triggered_principles", []),
                "reason": data.get("reason", ""),
                "recommended_action": data.get("recommended_action", "pass"),
            }
        except Exception:
            return {
                "is_dangerous": False,
                "risk_level": "low",
                "triggered_principles": [],
                "reason": "constitutional eval parse error",
                "recommended_action": "pass",
            }

    # ── Verdict application ───────────────────────────────────────────────────

    async def _apply_verdict(self, entry: MemoryEntry, probe: ProbeResult) -> None:
        """
        Apply probe verdict to the entry and update the memory bank (Stage 3).
        """
        embedding = await self._immune_detector.embed(entry.content)

        if probe.recommended_action == "quarantine":
            # Quarantine in store
            self._store.update_safety(
                entry.entry_id,
                is_unsafe=True,
                reason=f"scanner:{probe.reason[:120]}",
            )
            # Append SHADOW_EXEC_UNSAFE to entry's audit trail
            entry.add_audit_event(
                AuditEvent(
                    event_type=AuditEventType.SHADOW_EXEC_UNSAFE,
                    actor="scanner.periodic",
                    detail=probe.reason,
                    metadata={
                        "risk_level": probe.risk_level,
                        "triggered_principles": probe.triggered_principles,
                        "fast_path": probe.fast_path,
                    },
                )
            )
            # Add to attack short-term memory (will be promoted after cycle)
            self._memory_bank.add_short_term(embedding, "attack", entry.content)
            self._audit_logger.log_event(
                entry,
                entry.audit_trail[-1],
            )

        elif probe.recommended_action == "decay":
            entry.apply_trust_decay(
                actor="scanner.periodic",
                decay_factor=self._DECAY_FACTOR_MEDIUM,
                reason=f"scanner:medium_risk:{probe.reason[:80]}",
            )
            self._store.upsert(entry)
            entry.add_audit_event(
                AuditEvent(
                    event_type=AuditEventType.SHADOW_EXEC_UNSAFE,
                    actor="scanner.periodic",
                    detail=f"medium risk — trust decayed: {probe.reason}",
                    metadata={"risk_level": probe.risk_level},
                )
            )
            self._audit_logger.log_event(entry, entry.audit_trail[-1])

        else:  # pass
            entry.add_audit_event(
                AuditEvent(
                    event_type=AuditEventType.SHADOW_EXEC_SAFE,
                    actor="scanner.periodic",
                    detail="scanner: entry passed constitutional check",
                    metadata={"risk_level": probe.risk_level},
                )
            )
            self._store.upsert(entry)
            # Add to benign short-term memory
            self._memory_bank.add_short_term(embedding, "benign", entry.content)
            self._audit_logger.log_event(entry, entry.audit_trail[-1])
