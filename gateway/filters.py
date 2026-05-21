"""
Task 2 (sync path) — PII detection/masking + prompt-injection filtering.

SyncFilter runs on every write request before the entry is created.
It is intentionally fast (pure regex, no network calls) so it never
adds latency to the hot path.

Injection patterns cover the attack families from the spec:
  - MINJA-style instruction overrides
  - DAN / developer-mode jailbreaks
  - Fake system-tag injections (MemoryGraft)
  - System-prompt override attempts (PoisonedRAG)

PII patterns flag but do NOT block by default; content is masked
with [TYPE_REDACTED] placeholders before the MemoryEntry is created.
"""

import re
from dataclasses import dataclass


@dataclass
class FilterResult:
    blocked: bool
    reasons: list[str]      # injection pattern labels that fired
    pii_found: list[str]    # PII type names found
    warnings: list[str]     # human-readable warning strings


class SyncFilter:
    """Synchronous content filter: injection detection + PII masking."""

    # ── PII patterns (warn + mask, do not block) ──────────────────────────────
    _PII: dict[str, re.Pattern] = {
        "EMAIL":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I),
        "PHONE_US":    re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "CREDIT_CARD": re.compile(r"\b\d{4}[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}\b"),
        "SSN":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "IPV4":        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    }

    # ── Injection patterns (block immediately) ────────────────────────────────
    _INJECTIONS: list[tuple[re.Pattern, str]] = [
        # Classic instruction-override attacks (MINJA family)
        (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
         "injection:ignore_instructions"),
        (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
         "injection:disregard_instructions"),
        (re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
         "injection:forget_instructions"),
        # Jailbreak modes
        (re.compile(r"\bdan\s+mode\b", re.I),                "jailbreak:dan_mode"),
        (re.compile(r"\bdeveloper\s+mode\b", re.I),           "jailbreak:developer_mode"),
        (re.compile(r"\bdo\s+anything\s+now\b", re.I),        "jailbreak:do_anything_now"),
        (re.compile(r"\bjailbreak\b", re.I),                  "jailbreak:explicit"),
        # Persona override / evil-AI prompts
        (re.compile(
            r"act\s+as\s+(if\s+you\s+(are|were)\s+)?a?\s*(malicious|evil|unrestricted|unfiltered)",
            re.I),                                             "injection:act_as_evil"),
        (re.compile(
            r"you\s+are\s+now\s+a?\s*(different|new|evil|malicious)\s+\w+",
            re.I),                                             "injection:persona_override"),
        # Fake system / context tags (MemoryGraft, PoisonedRAG)
        (re.compile(r"\[SYSTEM\]|\<\s*/?system\s*\>", re.I), "injection:fake_system_tag"),
        (re.compile(r"system\s+prompt\s*[:=]", re.I),         "injection:system_prompt_override"),
    ]

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, text: str) -> FilterResult:
        """
        Scan text for injection patterns and PII.
        Returns FilterResult; blocked=True means the entry must not be stored.
        """
        reasons: list[str] = []
        pii_found: list[str] = []
        warnings: list[str] = []

        for pattern, label in self._INJECTIONS:
            if pattern.search(text):
                reasons.append(label)

        for pii_type, pattern in self._PII.items():
            if pattern.search(text):
                pii_found.append(pii_type)
                warnings.append(f"pii_detected:{pii_type}")

        return FilterResult(
            blocked=len(reasons) > 0,
            reasons=reasons,
            pii_found=pii_found,
            warnings=warnings,
        )

    def mask_pii(self, text: str) -> str:
        """Replace all detected PII with [TYPE_REDACTED] placeholders."""
        for pii_type, pattern in self._PII.items():
            text = pattern.sub(f"[{pii_type}_REDACTED]", text)
        return text

    def check_and_mask(self, text: str) -> tuple[FilterResult, str]:
        """
        Convenience: run check then mask PII in one call.
        Returns (FilterResult, masked_text).
        If blocked, masked_text is the original (caller should reject before storing).
        """
        result = self.check(text)
        masked = self.mask_pii(text) if result.pii_found else text
        return result, masked
