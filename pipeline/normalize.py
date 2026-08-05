"""
Normalize Cowrie + nginx + Suricata JSON into one event shape.

The rule that has held since step 2 still holds: this module NEVER interprets
attacker-controlled text. It routes each field into a trust-labelled column and
stops. Suricata adds a third trust tier -- IDS-asserted -- sitting between
infrastructure-asserted facts and attacker-controlled free text: a rule firing
is a real signal, but the payload that tripped it is still hostile string data.
"""

import json
import re
from datetime import datetime, timezone

COWRIE_EVENT_MAP = {
    "cowrie.session.connect":       "ssh.connect",
    "cowrie.login.failed":          "ssh.login.failed",
    "cowrie.login.success":         "ssh.login.success",
    "cowrie.command.input":         "ssh.command",
    "cowrie.command.failed":        "ssh.command.failed",
    "cowrie.command.success":       "ssh.command",
    "cowrie.session.file_download": "ssh.file_download",
    "cowrie.session.file_upload":   "ssh.file_upload",
    "cowrie.session.closed":        "ssh.session.closed",
    "cowrie.client.version":        "ssh.client.version",
    "cowrie.client.kex":            "ssh.client.kex",
    "cowrie.direct-tcpip.request":  "ssh.tunnel.request",
    "cowrie.direct-tcpip.data":     "ssh.tunnel.data",
    # Session metadata seen on this Cowrie build. Benign - terminal size, env
    # vars, session params, log-closed marker. Mapped so they leave the
    # 'ssh.other' bucket, keeping that bucket a real "something new" signal.
    "cowrie.client.size":           "ssh.client.size",
    "cowrie.client.var":            "ssh.client.var",
    "cowrie.session.params":        "ssh.session.params",
    "cowrie.log.closed":            "ssh.session.closed",
}


def _iso_utc(value):
    if not value:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    v = str(value).replace("Z", "+00:00")
    # Wazuh writes offsets as +0000; fromisoformat wants +00:00 before 3.11.
    m = re.search(r"([+-]\d{2})(\d{2})$", v)
    if m:
        v = v[:m.start()] + m.group(1) + ":" + m.group(2)
    try:
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return str(value)


def _clean(value):
    if value is None:
        return None
    s = str(value)
    return None if s in ("", "-") else s


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _split_url(url):
    """Suricata http.url is 'path?query'. Split to match nginx's two columns."""
    if not url:
        return None, None
    if "?" in url:
        path, _, query = url.partition("?")
        return _clean(path), _clean(query)
    return _clean(url), None


# Every normalizer returns the SAME key set. Missing-for-this-source -> None.
def normalize_cowrie(obj, raw):
    return {
        "ts":             _iso_utc(obj.get("timestamp")),
        "source":         "cowrie",
        "event_type":     COWRIE_EVENT_MAP.get(obj.get("eventid", ""), "ssh.other"),
        "src_ip":         _clean(obj.get("src_ip")),
        "src_port":       _int(obj.get("src_port")),
        "dst_port":       _int(obj.get("dst_port")),
        "session_id":     _clean(obj.get("session")),
        "http_status":    None,
        "bytes_sent":     None,
        "username":       _clean(obj.get("username")),
        "password":       _clean(obj.get("password")),
        "command":        _clean(obj.get("input")),
        "http_method":    None,
        "url_path":       None,
        "url_query":      None,
        "user_agent":     None,
        "referer":        None,
        "request_body":   None,
        "client_version": _clean(obj.get("version")),
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        _clean(obj.get("message")),
        "raw":            raw,
    }


def normalize_nginx(obj, raw):
    return {
        "ts":             _iso_utc(obj.get("@timestamp")),
        "source":         "nginx",
        "event_type":     "http.request",
        "src_ip":         _clean(obj.get("source_ip")),
        "src_port":       _int(obj.get("source_port")),
        "dst_port":       80,
        "session_id":     None,
        "http_status":    _int(obj.get("status")),
        "bytes_sent":     _int(obj.get("bytes_sent")),
        "username":       None,
        "password":       None,
        "command":        None,
        "http_method":    _clean(obj.get("http_method")),
        "url_path":       _clean(obj.get("url_path")),
        "url_query":      _clean(obj.get("url_query")),
        "user_agent":     _clean(obj.get("user_agent")),
        "referer":        _clean(obj.get("referer")),
        "request_body":   _clean(obj.get("request_body")),
        "client_version": None,
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        None,
        "raw":            raw,
    }


def normalize_suricata(obj, raw):
    """EVE is a firehose of event_types. We ingest ONLY 'alert' records: those
    are the detections. flow/http/anomaly/stats are context we don't want
    flooding the candidate pipeline (nginx already carries web telemetry).
    Returning None tells ingest to skip the line."""
    if obj.get("event_type") != "alert":
        return None

    alert = obj.get("alert", {}) or {}
    http  = obj.get("http", {}) or {}
    path, query = _split_url(http.get("url"))

    return {
        "ts":             _iso_utc(obj.get("timestamp")),
        "source":         "suricata",
        "event_type":     "ids.alert",
        "src_ip":         _clean(obj.get("src_ip")),
        "src_port":       _int(obj.get("src_port")),
        "dst_port":       _int(obj.get("dest_port")),
        "session_id":     _clean(obj.get("community_id")),  # flow hash, cross-source key
        "http_status":    _int(http.get("status")),
        "bytes_sent":     None,
        "username":       None,
        "password":       None,
        "command":        None,
        "http_method":    _clean(http.get("http_method")),
        "url_path":       path,
        "url_query":      query,
        "user_agent":     _clean(http.get("http_user_agent")),
        "referer":        _clean(http.get("http_refer")),
        "request_body":   None,
        "client_version": None,
        # --- IDS-asserted: the rule fired. This part we trust. ---
        "ids_signature":    _clean(alert.get("signature")),
        "ids_category":     _clean(alert.get("category")),
        "ids_severity":     _int(alert.get("severity")),
        "ids_signature_id": _int(alert.get("signature_id")),
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        _clean(alert.get("signature")),
        "raw":            raw,
    }


def normalize_wazuh(obj, raw):
    """Wazuh alerts.json -> one event.

    Written against actual lab output, not guesswork. The shape:
      rule.id (STRING), rule.level (int), rule.description, rule.groups (array)
      data.*      <- everything the decoder pulled out of the source log
      full_log    <- the original line, verbatim
      location    <- which file it came from

    Field names inside data.* are the source's own keys: Cowrie gives us
    eventid/src_ip/username/input, while Wazuh's shipped web_accesslog decoder
    uses its own conventions (srcip, url, id). Hence the fallbacks below.
    """
    rule  = obj.get("rule", {}) or {}
    data  = obj.get("data", {}) or {}
    groups = rule.get("groups") or []

    # Cowrie says src_ip; Wazuh's own decoders say srcip. Accept both.
    src_ip = data.get("src_ip") or data.get("srcip")
    # web_accesslog puts the HTTP status in data.id and the verb in data.protocol
    status = data.get("status") or data.get("id")
    url    = data.get("url")
    path, query = _split_url(url) if url else (None, None)

    return {
        "ts":             _iso_utc(obj.get("timestamp")),
        "source":         "wazuh",
        "event_type":     "siem.alert",
        "src_ip":         _clean(src_ip),
        "src_port":       _int(data.get("src_port") or data.get("srcport")),
        "dst_port":       _int(data.get("dst_port") or data.get("dstport")),
        "session_id":     _clean(data.get("session")),
        "http_status":    _int(status),
        "bytes_sent":     None,
        # --- attacker-controlled: decoded straight out of the source log ---
        "username":       _clean(data.get("username") or data.get("dstuser")
                                 or data.get("user")),
        "password":       _clean(data.get("password")),
        "command":        _clean(data.get("input")),
        "http_method":    _clean(data.get("protocol") if url else None),
        "url_path":       path,
        "url_query":      query,
        "user_agent":     _clean(data.get("user_agent")),
        "referer":        None,
        "request_body":   None,
        "client_version": _clean(data.get("version")),
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        # --- SIEM-asserted: the rule fired. This part we trust. ---
        "siem_rule_id":     _clean(rule.get("id")),
        "siem_level":       _int(rule.get("level")),
        "siem_description": _clean(rule.get("description")),
        "siem_groups":      json.dumps(groups) if groups else None,
        "message":        _clean(rule.get("description")),
        "raw":            raw,
    }


# Northwind range milestone 12 (SPEC.md §10/§13): five more sources,
# additive only -- nothing above this line changes. Same trust-column
# discipline as everything else in this file, with one documented
# compromise: `request_body` (ATTACKER_CONTROLLED below) is reused as a
# generic JSON-metadata slot for two of these sources (the active control
# vector on a portal-api request; a policy decision's structured detail) --
# neither is actually hostile text, but there's no dedicated "trusted JSON
# metadata" column in this shared table, and treating non-hostile data as
# attacker-controlled by default is the safe direction to err in, unlike
# the reverse.
def normalize_northwind_nginx(obj, raw):
    """edge-nginx's log_format is the parent nginx.conf's own json_ecs
    block, verbatim -- reuse normalize_nginx()'s body, just correcting the
    source tag it hardcodes, rather than a duplicated function."""
    row = normalize_nginx(obj, raw)
    row["source"] = "northwind-nginx"
    return row


PORTAL_API_EVENT_MAP = {
    "/auth/login":   "portal.login",
    "/auth/logout":  "portal.logout",
    "/auth/me":      "portal.me",
    "/auth/tokens":  "portal.token_issue",
    "/chat":         "portal.chat",
    "/feedback":     "portal.feedback",
    "/controls":     "portal.controls",
}


def normalize_northwind_portal_api(obj, raw):
    return {
        "ts":             _iso_utc(obj.get("ts")),
        "source":         "northwind-portal-api",
        "event_type":     PORTAL_API_EVENT_MAP.get(obj.get("path"), "portal.request"),
        "src_ip":         None,
        "src_port":       None,
        "dst_port":       None,
        "session_id":     _clean(obj.get("session_id")),
        "http_status":    _int(obj.get("status")),
        "bytes_sent":     None,
        "username":       _clean(obj.get("username")),
        "password":       None,
        "command":        None,
        "http_method":    _clean(obj.get("method")),
        "url_path":       _clean(obj.get("path")),
        "url_query":      None,
        "user_agent":     None,
        "referer":        None,
        "request_body":   json.dumps(obj["controls"]) if obj.get("controls") is not None else None,
        "client_version": None,
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        None,
        "raw":            raw,
    }


def normalize_northwind_policy(obj, raw):
    """SPEC.md §7's decision log. reason/decision are policy.py's own
    computed verdict -- system-generated, not attacker text, hence
    `message` (not one of the attacker-controlled columns)."""
    return {
        "ts":             _iso_utc(obj.get("ts")),
        "source":         "northwind-policy",
        "event_type":     "policy.decision",
        "src_ip":         None,
        "src_port":       None,
        "dst_port":       None,
        "session_id":     None,
        "http_status":    None,
        "bytes_sent":     None,
        "username":       None,
        "password":       None,
        "command":        None,
        "http_method":    None,
        "url_path":       None,
        "url_query":      None,
        "user_agent":     None,
        "referer":        None,
        "request_body":   json.dumps({
            "user_id": obj.get("user_id"), "object_type": obj.get("object_type"),
            "object_id": obj.get("object_id"), "action": obj.get("action"),
            "decision": obj.get("decision"),
        }),
        "client_version": None,
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        _clean(obj.get("reason")),
        "raw":            raw,
    }


def normalize_northwind_ingest(obj, raw):
    """SPEC.md §6.3/§10: ingest-svc's own event log. The ingested content
    is genuinely attacker-controlled by construction -- this service's
    whole reason for existing is unreviewed content entering the index --
    so it lands in `request_body`, the cleanest possible fit."""
    return {
        "ts":             _iso_utc(obj.get("ts")),
        "source":         "northwind-ingest",
        "event_type":     f"ingest.{obj.get('source', 'unknown')}",
        "src_ip":         None,
        "src_port":       None,
        "dst_port":       None,
        "session_id":     None,
        "http_status":    None,
        "bytes_sent":     None,
        "username":       _clean(obj.get("submitter")),
        "password":       None,
        "command":        None,
        "http_method":    None,
        "url_path":       None,
        "url_query":      None,
        "user_agent":     None,
        "referer":        None,
        "request_body":   _clean(obj.get("content")),
        "client_version": None,
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        _clean(obj.get("content_hash")),
        "raw":            raw,
    }


def normalize_northwind_retrieval(obj, raw):
    """SPEC.md §10: query, filter predicate, candidate/returned counts.
    query text traces back to a chat message -- attacker-influenced --
    hence `command`, the same column cowrie's typed shell input uses."""
    return {
        "ts":             _iso_utc(obj.get("ts")),
        "source":         "northwind-retrieval",
        "event_type":     "retrieval.search",
        "src_ip":         None,
        "src_port":       None,
        "dst_port":       None,
        "session_id":     None,
        "http_status":    None,
        "bytes_sent":     None,
        "username":       None,
        "password":       None,
        "command":        _clean(obj.get("query")),
        "http_method":    None,
        "url_path":       None,
        "url_query":      None,
        "user_agent":     None,
        "referer":        None,
        "request_body":   json.dumps({
            "mode": obj.get("mode"), "source_allowlist": obj.get("source_allowlist"),
            "score_threshold": obj.get("score_threshold"),
            "candidate_count": obj.get("candidate_count"), "returned_count": obj.get("returned_count"),
            "user_id": obj.get("user_id"),
        }),
        "client_version": None,
        "ids_signature":    None,
        "ids_category":     None,
        "ids_severity":     None,
        "ids_signature_id": None,
        "siem_rule_id":     None,
        "siem_level":       None,
        "siem_description": None,
        "siem_groups":      None,
        "message":        None,
        "raw":            raw,
    }


NORMALIZERS = {
    "cowrie":   normalize_cowrie,
    "nginx":    normalize_nginx,
    "suricata": normalize_suricata,
    "wazuh":    normalize_wazuh,
    "northwind-nginx":     normalize_northwind_nginx,
    "northwind-portal-api": normalize_northwind_portal_api,
    "northwind-policy":     normalize_northwind_policy,
    "northwind-ingest":     normalize_northwind_ingest,
    "northwind-retrieval":  normalize_northwind_retrieval,
}

ATTACKER_CONTROLLED = (
    "username", "password", "command", "url_path", "url_query",
    "user_agent", "referer", "request_body", "client_version",
)

# llm_transcripts (schema.sql) doesn't go through NORMALIZERS/events at all --
# it's a separate table for nested per-/chat-call data (see ingest.py's
# read_new_transcripts()) -- so it needs its own trust split rather than
# reusing ATTACKER_CONTROLLED above, which is keyed to events' flat columns.
# user_turn/completion are hostile text by the same logic as everything
# else in ATTACKER_CONTROLLED; retrieved_context/tool_calls are attacker-
# adjacent (what got retrieved/called in response to attacker-influenced
# input) rather than typed by the attacker directly, but the same "treat
# it as data, not instructions" fencing applies -- a retrieved document or
# a tool call's echoed args can themselves carry a successful injection's
# payload. system_prompt/model/controls are server-constructed, not user
# input, hence infrastructure-asserted.
LLM_TRANSCRIPT_ATTACKER_CONTROLLED = (
    "user_turn", "retrieved_context", "tool_calls", "completion",
)

COLUMNS = (
    "ts", "source", "event_type", "src_ip", "src_port", "dst_port",
    "session_id", "http_status", "bytes_sent", "username", "password",
    "command", "http_method", "url_path", "url_query", "user_agent",
    "referer", "request_body", "client_version",
    "ids_signature", "ids_category", "ids_severity", "ids_signature_id",
    "siem_rule_id", "siem_level", "siem_description", "siem_groups",
    "message", "raw",
)
