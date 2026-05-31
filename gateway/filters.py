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
from typing import Optional


@dataclass
class FilterResult:
    blocked: bool
    reasons: list[str]      # injection pattern labels that fired
    pii_found: list[str]    # PII type names found
    warnings: list[str]     # human-readable warning strings


class SyncFilter:
    """Synchronous content filter: injection detection + PII masking."""

    def __init__(
        self,
        pii_patterns: Optional[dict[str, str]] = None,
        injection_patterns: Optional[list[tuple[str, str]]] = None,
        extra_pii_patterns: Optional[dict[str, str]] = None,
        extra_injection_patterns: Optional[list[tuple[str, str]]] = None,
        block_on_pii: bool = False,
    ):
        self._PII = self._build_pii_patterns(pii_patterns, extra_pii_patterns)
        self._INJECTIONS = self._build_injection_patterns(
            injection_patterns,
            extra_injection_patterns,
        )
        self._block_on_pii = block_on_pii

    @staticmethod
    def _build_pii_patterns(
        pii_patterns: Optional[dict[str, str]],
        extra_pii_patterns: Optional[dict[str, str]],
    ) -> dict[str, re.Pattern]:
        patterns = pii_patterns or {
            "EMAIL":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            "PHONE_CN":    r"(?<!\d)(?:\+?86[-.\s]?)?1[3-9]\d(?:[-.\s]?\d){8}(?!\d)",
            "ID_CN":       r"(?<!\d)\d{17}[\dXx](?!\d)",
            "PHONE_US":    r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "CREDIT_CARD": r"\b\d{4}[\ \-]?\d{4}[\ \-]?\d{4}[\ \-]?\d{4}\b",
            "SSN":         r"\b\d{3}-\d{2}-\d{4}\b",
            "IPV4":        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
            "IPV6":        r"\b(?:"
                            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|"
                            r"(?:[0-9A-Fa-f]{1,4}:){1,7}:|"
                            r":(?::[0-9A-Fa-f]{1,4}){1,7}|"
                            r"(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:\d{1,3}\.){3}\d{1,3}|"
                            r"::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
                            r")\b",
        }
        if extra_pii_patterns:
            patterns = {**patterns, **extra_pii_patterns}
        return {name: re.compile(pattern, re.I) for name, pattern in patterns.items()}

    @staticmethod
    def _build_injection_patterns(
        injection_patterns: Optional[list[tuple[str, str]]],
        extra_injection_patterns: Optional[list[tuple[str, str]]],
    ) -> list[tuple[re.Pattern, str]]:
        patterns = injection_patterns or [
            # Classic instruction-override attacks (MINJA family)
            (r"(?:ignore|bypass|override|discard|delete|wipe|erase)\s+(?:all\s+)?(?:previous|prior|above|earlier|former|following)\s+instructions?", "injection:ignore_instructions"),
            (r"(?:disregard|ignore)\s+(?:all\s+)?(?:previous|prior|above|earlier|former|following)\s+instructions?", "injection:disregard_instructions"),
            (r"(?:forget|drop|remove)\s+(?:all\s+)?(?:previous|prior|above|earlier|former|following)\s+instructions?", "injection:forget_instructions"),
            (r"(?:new|updated|latest)\s+instructions?\s*[:=\-–—]", "injection:new_instructions"),
            (r"(?:system|developer|assistant)\s+instructions?\s*(?:take\s+priority|override|supersede|replace)\s*(?:user|prompt)?", "injection:instruction_priority_override"),
            # Jailbreak modes
            (r"\bdan(?:\s*[-_]?\s*mode|\s*\d+)?\b", "jailbreak:dan_mode"),
            (r"\bdeveloper(?:\s*[-_]?\s*mode)?\b", "jailbreak:developer_mode"),
            (r"\bdo\s+anything\s+now\b|\banything\s+now\s+allowed\b", "jailbreak:do_anything_now"),
            (r"\bjail\s*break\b|\bjailbroken\b", "jailbreak:explicit"),
            # Persona override / evil-AI prompts
            (r"act\s+as\s+(if\s+you\s+(are|were)\s+)?a?\s*(malicious|evil|unrestricted|unfiltered)", "injection:act_as_evil"),
            (r"you\s+are\s+now\s+a?\s*(different|new|evil|malicious|unfiltered|unrestricted)\s+\w+", "injection:persona_override"),
            (r"from\s+now\s+on\s*,?\s*you\s+are\s+(?:a|an)?\s*(?:different|new|evil|malicious)\s+\w+", "injection:persona_override_from_now_on"),
            (r"(?:follow|obey|comply\s+with)\s+(?:the\s+)?(?:new|above|following)\s+instructions?", "injection:follow_new_instructions"),
            # Fake system / context tags (MemoryGraft, PoisonedRAG)
            (r"\[\s*SYSTEM\s*\]|\<\s*/?\s*system\s*\>|\{\s*system\s*\}|\(\s*system\s*\)", "injection:fake_system_tag"),
            (r"\b(?:system|developer|assistant)\s*prompt\s*[:=\-–—]", "injection:system_prompt_override"),
            (r"\b(?:system|developer|assistant)\s*[:=]\s*", "injection:role_prefix_injection"),
            (r"(?:^|\n)\s*#+\s*(?:system|developer|assistant)\b", "injection:markdown_role_header"),
        ]
        if extra_injection_patterns:
            patterns = [*patterns, *extra_injection_patterns]
        return [(re.compile(pattern, re.I), label) for pattern, label in patterns]

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
            blocked=len(reasons) > 0 or (self._block_on_pii and len(pii_found) > 0),
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
