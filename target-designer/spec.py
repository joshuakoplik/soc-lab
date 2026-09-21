#!/usr/bin/env python3
"""The target spec -- the artifact the design stage produces and the build /
verify / save stages consume.

A spec captures everything needed to stand up ONE chainable lab host: the two
(or more) published CVEs it instantiates, the docker build recipe for the
vulnerable stack, what ends up listening (for recon + telemetry), the chain
narrative (operator-side ground truth / oracle -- prose referencing public CVE
IDs, never weaponized exploit code), and NON-exploit verification checks
(service liveness + vulnerable-version presence) used to confirm the box stood
up correctly without firing an exploit at it.

Plain dataclasses + dict round-trip; stdlib only.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
from dataclasses import dataclass, field


@dataclass
class CVERef:
    cve: str
    product: str = ""          # vendor:product
    version: str = ""          # the vulnerable version to pin
    role: str = ""             # "foothold" | "privesc"
    summary: str = ""          # one line, from the advisory


@dataclass
class VerificationCheck:
    """A NON-exploit check that the vulnerable box stood up correctly. Kinds:
    - "http": GET path, expect substring/status in the response.
    - "cmd":  run a shell command in the container, expect substring in output.
    - "port": expect a TCP port open.
    Never an exploitation step -- liveness and version presence only."""
    name: str
    kind: str                  # http | cmd | port
    check: str                 # path / command / port
    expect: str = ""           # substring or status to look for


@dataclass
class TargetSpec:
    id: str
    title: str
    base_image: str
    foothold: CVERef
    privesc: CVERef
    chain_narrative: str                       # operator ground-truth, prose only
    dockerfile_steps: list[str] = field(default_factory=list)  # RUN/COPY/ENV lines
    listening: list[dict] = field(default_factory=list)        # [{port, service, proto}]
    verification: list[VerificationCheck] = field(default_factory=list)
    difficulty_notes: str = ""
    designed_by: str = ""                       # model id
    created_at: str = ""
    extra: dict = field(default_factory=dict)   # room to grow, no schema churn

    # ---- serialization -------------------------------------------------
    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TargetSpec":
        d = dict(d)
        d["foothold"] = CVERef(**d["foothold"])
        d["privesc"] = CVERef(**d["privesc"])
        d["verification"] = [VerificationCheck(**v) for v in d.get("verification", [])]
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    def save(self, targets_dir: str) -> str:
        """Write spec.json under targets/<id>/ and return that directory."""
        out = os.path.join(targets_dir, self.id)
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "spec.json"), "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out


def new_id(foothold_cve: str, privesc_cve: str) -> str:
    """A stable, human-legible id: date + the two CVE tails."""
    day = datetime.date.today().strftime("%Y%m%d")

    def tail(cve: str) -> str:
        return cve.replace("CVE-", "").replace("-", "") if cve else "none"

    return f"td-{day}-{tail(foothold_cve)}-{tail(privesc_cve)}"
