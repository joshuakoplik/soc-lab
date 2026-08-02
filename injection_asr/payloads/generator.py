"""
Seeded, reproducible payload generation across all four attack classes.

Default backend ("template") is the built-in generator in imperative.py /
false_context.py / field_splitting.py / evasion.py -- pure Python, no
network, runs standalone. "ollama", "fireworks", and "garak" are optional
pluggable backends for additional variants; none is imported (and none has
to be installed/running/credentialed) unless explicitly requested via
--backend.
"""

import random

from . import evasion, false_context, field_splitting, imperative
from .. import config

CLASS_MODULES = {
    "imperative": imperative,
    "false_context": false_context,
    "field_splitting": field_splitting,
    "evasion": evasion,
}


def generate_all(seed, n_per_class, classes=None, gateway_ip=config.DEFAULT_GATEWAY_IP,
                  backend="template", backend_model=None):
    classes = classes or list(CLASS_MODULES)
    unknown = [c for c in classes if c not in CLASS_MODULES]
    if unknown:
        raise ValueError(f"unknown attack class(es): {unknown}; choose from {list(CLASS_MODULES)}")

    rng = random.Random(seed)
    payloads = []
    for cls in classes:
        mod = CLASS_MODULES[cls]
        if cls == "false_context":
            payloads.extend(mod.generate(rng, n_per_class, gateway_ip=gateway_ip))
        else:
            payloads.extend(mod.generate(rng, n_per_class))

    if backend != "template":
        payloads.extend(_generate_external(backend, backend_model, rng, classes, gateway_ip))

    return payloads


def _generate_external(backend, model, rng, classes, gateway_ip):
    if backend == "ollama":
        from . import ollama_backend
        return ollama_backend.generate(rng, model or "qwen3:8b")
    if backend == "fireworks":
        from . import fireworks_backend
        return fireworks_backend.generate(rng, model or "accounts/fireworks/models/glm-5p1")
    if backend == "garak":
        from . import garak_backend
        return garak_backend.generate(rng)
    raise ValueError(f"unknown payload backend: {backend!r} (choose template/ollama/fireworks/garak)")
