"""
Computes events.llm_view: the same event, stripped of anything that's mostly
bytes rather than signal, for the tools in agent.py to hand the LLM instead
of the raw source line.

Why this exists: Suricata's EVE JSON captures full HTTP bodies on flagged
transactions -- base64 request/response payloads, often the entire page body
of whatever was served. A single event can run 12,000+ chars, nearly all of
it a copy of e.g. the Juice Shop homepage, not anything a triage analyst
reasons over. That gets resent on every subsequent tool-call turn for a
candidate, compounding fast (see AGENT_BRIEF-adjacent cost analysis this
session: ~34K chars just for one query_events() call on a 2-3 event
candidate). llm_view is computed once at ingest time so the agent tools never
have to pay that cost per-call.

raw stays exactly as-is, always -- this is additive, not a replacement. See
schema.sql: "Never silently drop telemetry" applies to raw; llm_view is a
second, size-bounded view derived from it, not instead of it.
"""

import copy
import hashlib
import json
from collections import Counter

# First N chars of a stripped field kept as a preview -- enough for a human
# or the model to recognize what kind of content it was, not enough to
# reconstitute the cost we're trying to avoid.
PREVIEW_CHARS = 300

# Any string field this long or longer gets stripped, UNLESS its key is on
# STRUCTURED_FIELD_ALLOWLIST below. Suricata's own metadata fields (ports,
# signatures, flow counters, ...) never get anywhere near this; only
# actual body/payload blobs do.
STRIP_THRESHOLD_CHARS = 1000

# After compute_llm_view + json.dumps, warn (never fail) if the result is
# still over this. This is an ANOMALY threshold, not a target size -- most
# events, especially Suricata HTTP alerts carrying two stripped body
# previews plus their hashes, normally land around 2.2-2.5K chars post-strip,
# and that's expected, not a problem (see backfill run against 3384 real
# events: p50=2230, p99=3877, max=4032 -- consistently reduced from raw
# sizes up to ~12-13K). This threshold is set comfortably above that
# observed ceiling specifically so it stays silent on normal, well-stripped
# events and only fires if some future field shape slips past the strip
# pass entirely and stays close to raw size.
LLM_VIEW_SIZE_WARN_CHARS = 6000

# Named explicitly per spec: HTTP body fields always get the preview+hash
# treatment, even in the (unlikely) case one happens to be short -- these are
# never the actual evidence a triage analyst reasons over, base64 or not.
ALWAYS_PREVIEW_FIELDS = {"http_request_body", "http_response_body"}

# Known-small, known-structured fields that are never stripped by the
# generic size pass, even if some pathological input made them huge --
# these (or their Suricata sub-object equivalents) are the actual signal:
# IDs, addresses, ports, protocol/signature metadata, flow counters. Field
# names only, not paths, since Suricata reuses names like "size" and
# "action" across several sub-objects.
STRUCTURED_FIELD_ALLOWLIST = {
    "timestamp", "flow_id", "in_iface", "event_type", "src_ip", "src_port",
    "dest_ip", "dest_port", "proto", "ip_v", "pkt_src", "community_id",
    "tx_id", "app_proto", "direction", "ts_progress", "tc_progress", "stream",
    "gid", "rev", "action", "signature", "signature_id", "category",
    "severity", "metadata", "affected_product", "attack_target", "confidence",
    "created_at", "deployment", "performance_impact", "reviewed_at",
    "signature_severity", "updated_at",
    "hostname", "url", "http_method", "http_content_type", "http_user_agent",
    "xff", "status", "length", "protocol",
    "filename", "gaps", "state", "stored", "size",
    "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
    "start",
}

# Run-scoped: how many times each field name got stripped. Stripping an HTTP
# body happens on nearly every Suricata alert -- routine, not exceptional --
# so logging it is a single aggregate summary per run (see print_strip_summary
# in ingest.py's summarize() and backfill_llm_views.py), not one print per
# event, which would just flood the ingest log for a case that isn't a
# problem.
_strip_counts = Counter()


def reset_strip_counts():
    _strip_counts.clear()


def _preview_and_hash(key, value):
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return {f"{key}_preview": value[:PREVIEW_CHARS], f"{key}_sha256": digest}


def _strip_large_values(obj):
    """Recursively mutate obj in place, replacing any oversized string leaf
    (at any nesting depth, under any protocol sub-object -- http, smtp, dns,
    fileinfo, whatever) with a preview+hash pair, unless its key is on the
    structured-field allowlist. Catches http_request_body/http_response_body
    unconditionally (ALWAYS_PREVIEW_FIELDS) and anything else oversized by
    the same size-threshold check -- one mechanism for both, since a large
    base64 blob under an SMTP/DNS/fileinfo field we haven't seen a real
    sample of looks the same to this pass as an HTTP body does."""
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            value = obj[key]
            if isinstance(value, str) and key not in STRUCTURED_FIELD_ALLOWLIST:
                if key in ALWAYS_PREVIEW_FIELDS or len(value) > STRIP_THRESHOLD_CHARS:
                    _strip_counts[key] += 1
                    del obj[key]
                    obj.update(_preview_and_hash(key, value))
            elif isinstance(value, (dict, list)):
                _strip_large_values(value)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _strip_large_values(item)
    return obj


def compute_llm_view(raw_event: dict) -> dict:
    """Deep-copies raw_event and strips oversized/blob fields per
    _strip_large_values, returning a JSON-serializable dict safe to hand an
    LLM in place of the raw event. Pure function -- no logging, no DB access;
    see check_llm_view_size for the post-hoc size check (needs the row's
    event_id, which doesn't exist yet at the point this is normally called
    during ingest, before the INSERT)."""
    return _strip_large_values(copy.deepcopy(raw_event))


def check_llm_view_size(event_id, llm_view_json):
    """Not an assertion that raises -- a loud, never-fails print so an
    operator notices if some new field starts slipping past the strip pass
    instead of the cost silently creeping back in. Called by the caller
    (ingest.py / backfill_llm_views.py) after it has a real event_id."""
    size = len(llm_view_json)
    if size > LLM_VIEW_SIZE_WARN_CHARS:
        print(f"  [llm_view] WARNING: event_id={event_id} llm_view is {size} "
              f"chars, over the {LLM_VIEW_SIZE_WARN_CHARS}-char budget")
    return size


def print_strip_summary():
    """One aggregate line, not one line per event -- see _strip_counts."""
    if not _strip_counts:
        return
    parts = ", ".join(f"{k}={n}" for k, n in _strip_counts.most_common())
    print(f"  [llm_view] stripped fields this run: {parts}")
