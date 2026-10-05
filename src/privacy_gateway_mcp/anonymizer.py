"""Bidirectional anonymization.

Sensitive entities are detected by regex, replaced with stable, reversible
placeholders (``[EMAIL_1]``, ``[PHONE_2]`` ...), and can be re-hydrated later so the
caller sees real values while the cloud provider only ever sees placeholders.

Design notes
------------
* Detection is done on the *original* text in a single pass over non-overlapping
  spans, resolved by detector priority. This means placeholders can never be
  re-matched by a later detector (a subtle bug in naive replace-in-place code).
* Placeholders are *consistent*: the same value always maps to the same
  placeholder, so ``[EMAIL_1]`` in the response re-hydrates to the same address.
* Regex-based detection is intentionally dependency-free so the gateway runs on
  bare-metal with no model download. Swapping in an NER model (spaCy/Presidio)
  means implementing one method — see ``detect`` below.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .types import Entity, EntityType

# Módulo 11: valida el dígito verificador de un RUT escrito SIN puntos ni guion
# (ej. "123456785"), para no marcar cualquier número de 8-9 dígitos como RUT.
def _rut_concat_valido(s: str) -> bool:
    cuerpo, dv = s[:-1], s[-1].lower()
    if not cuerpo.isdigit():
        return False
    suma, mul = 0, 2
    for ch in reversed(cuerpo):
        suma += int(ch) * mul
        mul = 2 if mul == 7 else mul + 1
    resto = 11 - (suma % 11)
    esperado = "0" if resto == 11 else "k" if resto == 10 else str(resto)
    return esperado == dv


# Detectors in priority order. Earlier patterns win when spans overlap, so the
# more specific / higher-risk categories are listed first. An optional third
# element is a validator(matched_text) -> bool that filters candidate matches.
_DETECTORS: list[tuple] = [
    # API keys / tokens. The sk- class allows '-' and '_' so hyphenated keys are
    # caught: Anthropic 'sk-ant-api03-...' and OpenAI 'sk-proj-...'.
    (EntityType.SECRET, re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,})\b")),
    (EntityType.EMAIL, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    # Chilean RUT con separadores, e.g. 12.345.678-5 or 12345678-K
    (EntityType.RUT, re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")),
    # Card-like: 13-19 digits, optionally grouped by spaces or hyphens.
    # The span must END on a digit (trailing separators got glued to the next word).
    (EntityType.CARD, re.compile(r"\b\d(?:[ -]?\d){12,18}\b")),
    (EntityType.IPV4, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # Chilean mobile / international phone: +56 9 1234 5678, 912345678, etc.
    (EntityType.PHONE, re.compile(r"(?<![\w.])\+?(?:56)?\s?9(?:\s?\d){8}(?![\w])")),
    # Chilean landline (fijo). Requires +56 or an area code in parentheses to evitar
    # falsos positivos: "+56 32 2673000", "+56 2 2345 6789", "(32) 267 3000".
    (EntityType.PHONE, re.compile(r"(?<![\w.])(?:\+?56[\s-]?\d{1,2}|\(\d{1,2}\))[\s-]?\d{3,4}[\s-]?\d{4}(?![\w])")),
    # Chilean RUT SIN puntos ni guion (ej. "123456785"): candidato validado por módulo 11.
    (EntityType.RUT, re.compile(r"(?<![\w.-])\d{7,8}[\dkK](?![\w.-])"), _rut_concat_valido),
    # Money: $1.234.567, USD 1,200.50, 600000 CLP
    (EntityType.MONEY, re.compile(
        r"(?:(?:US)?\$\s?\d[\d.,]*|\b\d[\d.,]*\s?(?:USD|CLP|MXN|EUR|pesos|dólares|d[oó]lares))",
        re.IGNORECASE,
    )),
]


@dataclass
class RedactionResult:
    """The redacted text plus everything needed to reverse it."""

    redacted: str
    entities: list[Entity]
    # placeholder -> original value, for re-hydration.
    mapping: dict[str, str]


class Anonymizer:
    """Detects, redacts and re-hydrates sensitive entities."""

    def __init__(self, detectors=_DETECTORS) -> None:
        self._detectors = detectors

    def detect(self, text: str) -> list[tuple[int, int, EntityType, str]]:
        """Return non-overlapping ``(start, end, type, value)`` spans, left to right.

        Overlaps are resolved by detector priority (order in ``_DETECTORS``).
        """
        spans: list[tuple[int, int, EntityType, str]] = []
        taken: list[tuple[int, int]] = []
        for det in self._detectors:
            etype, pattern = det[0], det[1]
            validator = det[2] if len(det) > 2 else None
            for m in pattern.finditer(text):
                if validator is not None and not validator(m.group()):
                    continue  # candidate rejected (e.g. RUT with invalid check digit)
                start, end = m.start(), m.end()
                if any(start < t_end and end > t_start for t_start, t_end in taken):
                    continue  # overlaps a higher-priority match already claimed
                spans.append((start, end, etype, m.group()))
                taken.append((start, end))
        spans.sort(key=lambda s: s[0])
        return spans

    def redact(self, text: str) -> RedactionResult:
        """Replace detected entities with reversible placeholders."""
        spans = self.detect(text)

        # Assign consistent placeholders: same (type, value) -> same placeholder.
        counters: dict[EntityType, int] = {}
        value_to_placeholder: dict[tuple[EntityType, str], str] = {}
        mapping: dict[str, str] = {}
        entities: list[Entity] = []

        out: list[str] = []
        cursor = 0
        for start, end, etype, value in spans:
            key = (etype, value)
            placeholder = value_to_placeholder.get(key)
            if placeholder is None:
                counters[etype] = counters.get(etype, 0) + 1
                placeholder = f"[{etype.value}_{counters[etype]}]"
                value_to_placeholder[key] = placeholder
                mapping[placeholder] = value
                entities.append(Entity(type=etype, value=value, placeholder=placeholder))
            out.append(text[cursor:start])
            out.append(placeholder)
            cursor = end
        out.append(text[cursor:])

        return RedactionResult(redacted="".join(out), entities=entities, mapping=mapping)

    def rehydrate(self, text: str, mapping: dict[str, str]) -> str:
        """Replace placeholders with their original values.

        Longest placeholders first so ``[EMAIL_10]`` is restored before ``[EMAIL_1]``.
        """
        for placeholder in sorted(mapping, key=len, reverse=True):
            text = text.replace(placeholder, mapping[placeholder])
        return text

    def has_residual_sensitive(self, text: str) -> bool:
        """True if any sensitive entity is still present (used for fail-closed checks)."""
        return len(self.detect(text)) > 0
