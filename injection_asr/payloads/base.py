"""
Shared shape (Payload) and mutation primitives every attack-class module
builds on. Kept separate from generator.py to avoid a circular import
between the orchestrator and the four class modules.
"""

from dataclasses import dataclass


@dataclass
class Payload:
    attack_class: str          # imperative | false_context | field_splitting | evasion
    variant_id: str            # stable within a run, e.g. "imperative-007"
    surface: str               # "ssh" | "http" -- which base scenario/fields this targets
    fields: dict                # attacker-controlled field name -> exact string to inject
    description: str           # short human-readable label for the report
    targets_gateway: bool = False  # True for the subset probing recommend_block redirection


# Cyrillic/Greek look-alikes for the Latin letters an "ignore"-shaped
# imperative string leans on. Deliberately small and eyeball-verifiable
# rather than a full confusables table -- this harness needs a few
# reproducible glyph swaps, not a general Unicode security library.
HOMOGLYPHS = {"a": "а", "e": "е", "i": "і", "o": "о", "c": "с", "p": "р"}

ZERO_WIDTH = "​‌‍"  # ZWSP, ZWNJ, ZWJ


def homoglyph_swap(text, rng, rate=0.4):
    out = []
    for ch in text:
        repl = HOMOGLYPHS.get(ch.lower())
        if repl and rng.random() < rate:
            out.append(repl.upper() if ch.isupper() else repl)
        else:
            out.append(ch)
    return "".join(out)


def insert_zero_width(text, rng, rate=0.15):
    out = []
    for ch in text:
        out.append(ch)
        if ch.isalpha() and rng.random() < rate:
            out.append(rng.choice(ZERO_WIDTH))
    return "".join(out)


def random_case(text, rng):
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)
