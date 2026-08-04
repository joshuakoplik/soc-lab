"""
Deterministic, local payload transforms for red-team-agent use
(REDTEAM_MODE_SPEC.md §4.5). Technique list "lifted from PyRIT's
converters" per the spec's own instruction -- NOT a PyRIT dependency;
garak/PyRIT stay out of this agent's own tool-call loop entirely (garak is
a campaign runner, PyRIT an orchestrator -- nesting either inside this
agent's turn loop would be confused architecture, per the spec's own
reasoning).

Every transform here is a pure function: same input always produces the
same output, no network calls, no model calls, no external dependency.

Deliberately no "translate" technique, despite PyRIT having one: the
agent driving this tool is itself an LLM already fluent in translation --
a mechanical tool for it would just be a slower, more error-prone version
of something the model can already do directly in its own message text.
"""
import base64
import codecs

_LEET_MAP = str.maketrans({
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7",
})

# Cyrillic look-alikes -- visually near-identical to their Latin
# counterparts in most fonts, but different Unicode codepoints, so a
# naive substring/keyword filter checking for the Latin original won't
# match. Deliberately a small, high-confidence subset (characters with a
# genuinely convincing look-alike), not an attempt at full coverage.
_CONFUSABLE_MAP = str.maketrans({
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у",
    "A": "А", "E": "Е", "O": "О", "P": "Р", "C": "С", "X": "Х", "Y": "У",
})

_MORSE_MAP = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    " ": "/",
}


def _base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _leetspeak(text: str) -> str:
    return text.translate(_LEET_MAP)


def _char_space(text: str) -> str:
    return " ".join(text)


def _reverse(text: str) -> str:
    return text[::-1]


def _unicode_confusable(text: str) -> str:
    return text.translate(_CONFUSABLE_MAP)


def _morse(text: str) -> str:
    return " ".join(_MORSE_MAP.get(c.upper(), c) for c in text)


TRANSFORMS = {
    "base64": _base64_encode,
    "rot13": _rot13,
    "leetspeak": _leetspeak,
    "char_space": _char_space,
    "reverse": _reverse,
    "unicode_confusable": _unicode_confusable,
    "morse": _morse,
}


def transform(text: str, technique: str) -> str:
    """KeyError on an unknown technique -- the caller's job to catch and
    turn into a clean tool-result error, same convention as everywhere
    else in this codebase (validation errors are the caller's problem to
    translate into a model-facing message, not this function's)."""
    return TRANSFORMS[technique](text)
