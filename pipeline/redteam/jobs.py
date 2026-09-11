"""
Background jobs for the red-team agent: detached subprocesses whose lifecycle
OUTLIVES the agent turn that launched them.

Motivation (see the brief): the agent perseverates on hash cracking because a
foreground `john` run dies at a duration cap, returns nothing conclusive, and
leaves a task that looks unfinished-but-promising -- so the model keeps coming
back to it. Cracking is the one technique class with no natural failure signal
("is this hash crackable" only ever resolves to *not yet*). The fix is to let
that work terminate somewhere OTHER than the turn loop: the agent submits a
job, moves on, and learns the SETTLED result on a later turn, the way a person
leaves a crack running in another window.

This is NOT a subagent (no model call -- a crack is `john` with parameters, and
wrapping it in a reasoner adds cost and failure modes to do what a subprocess
does correctly) and NOT async tool execution in general (foreground tools are
unchanged). It is a detached OS process with its own liveness and its own
system-of-record.

Four load-bearing properties, each the fix to a specific failure the brief
calls out:

1. TERMINAL RESULTS THAT READ AS SETTLED. A crack that exhausts its wordlist
   reaches `exhausted` with a verdict that says "do not relaunch" -- not
   "0 recovered so far". A job that finishes having found nothing is a
   SUCCESSFUL job that produced a real answer; `job_results.outcome` and
   `produced_new_information` keep "completed" and "informative" as separate
   facts (the technique-ledger work depends on that). Parsing john's actual
   output to get this right is the one thing to get exactly right -- exit code
   does not tell you the outcome (see CrackJobType.parse_output).

2. PROVENANCE IN BOTH DIRECTIONS.
   - INPUT comes from a stored `loot` artifact (source_loot_id) + a selector,
     never from model-supplied text. A model that transcribes a hash out of a
     fetched exploit writeup has nowhere to put it; a "recovered" credential
     cannot originate anywhere but a real captured dump. A wrong selection
     fails VISIBLY at submit (JobInputError), no row written.
   - OUTPUT is written by the harness from the job's own files (the potfile +
     `john --show`), never summarized by the model. A recovered credential
     enters state_credentials only as a side effect of the supervisor
     finalizing -- so a win claiming a crack has a harness-written record to
     point at, and audit_session grounds on that, not on the model's prose.

3. LIVENESS WITHOUT PID IDENTITY. The supervisor holds an advisory flock on a
   HOST-LOCAL lockfile for its whole life. The kernel frees it on death for any
   reason; testing it needs no PID (LOCK_NB probe). So a reused PID can never
   make a dead job look alive, and a kill never signals an unrelated process --
   the pidfile is consulted ONLY to kill a job the lock says is alive. Works
   identically on the Linux container host and on macOS because it is a plain
   host process locking a plain host file -- NOT the docker bind mount, whose
   cross-VM flock semantics on Docker Desktop are unreliable.

4. A REAPER. A session that died hours ago must not leave a wordlist run
   competing with Ollama for the box. reap() adopts finished work, marks
   supervisors that died mid-run, and (on demand) kills over-wall orphans.

Run modes:
    import jobs                       # used by agent.py (submit/reap/render)
    python3 jobs.py run <job_id>      # the detached supervisor itself
    python3 jobs.py reap [--kill-orphans]   # used by reset.sh
"""

import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))   # pipeline/redteam
PIPELINE = os.path.dirname(HERE)                     # pipeline
ROOT = os.path.dirname(PIPELINE)                     # soc-lab root
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if PIPELINE not in sys.path:
    sys.path.insert(0, PIPELINE)
import executor as redteam_exec  # noqa: E402

_THIS_FILE = os.path.abspath(__file__)
DB_PATH = os.path.join(ROOT, "soc.db")

# Host-local advisory-lock directory (liveness). DELIBERATELY not under
# attacker/loot/ (the docker bind mount): on macOS Docker Desktop a flock
# across the VM/virtiofs boundary is unreliable, so the liveness holder is a
# plain host process locking a plain host file -- identical on Linux and mac.
# Gitignored; cleared by reset.sh.
JOBS_STATE_DIR = os.path.join(ROOT, ".jobs")

# The host also serves local models (Ollama) -- a second heavy crack while one
# is running starves inference. Host-wide cap, not per-session.
MAX_CONCURRENT_JOBS = int(os.environ.get("REDTEAM_MAX_CONCURRENT_JOBS", "1"))

# A crack is expected to be QUIET for long stretches (idle-detection is wrong
# for it, unlike an interactive scan), so the job's only time bound is this
# absolute wall backstop, not non-progress. A backstop, not a budget.
CRACK_MAX_WALL_S = int(os.environ.get("REDTEAM_CRACK_MAX_WALL_S", "3600"))

# A freshly-INSERTed job is 'running' with its lock not yet held (the
# supervisor hasn't started). Don't let reap() mistake that startup window for
# a dead job; give the supervisor this long to come up and take the lock.
STARTUP_GRACE_S = int(os.environ.get("REDTEAM_JOB_STARTUP_GRACE_S", "20"))

# Default wordlist INSIDE soc-attacker. attacker/Dockerfile ensures a plaintext
# rockyou lands here (Kali ships it gzipped; seclists carries it too).
DEFAULT_WORDLIST_CTR = os.environ.get("REDTEAM_CRACK_WORDLIST", "/usr/share/wordlists/rockyou.txt")

# PROMOTION (a foreground call still making progress past a threshold is moved
# to the background so the agent can work on something else meanwhile). This is
# a CONCURRENCY decision, distinct from idle-detection's correctness kill, and
# is harness-initiated -- the model never asks to background a call; the
# command already passed the normal gate. 0 disables it (the default): a
# promoted call uses a detach-to-FILE launch (output redirected to a loot file
# inside the container, never a docker-exec stdout pipe), specifically so the
# process survives the hand-off without a SIGPIPE -- the streaming monitored
# path CANNOT be detached mid-run for that reason, so promotion deliberately
# does not reuse it.
PROMOTE_AFTER_S = int(os.environ.get("REDTEAM_PROMOTE_AFTER_S", "0"))


class JobInputError(Exception):
    """A submit that can't be turned into a real job from a real artifact --
    a loot id that doesn't exist, or a selector that matches no usable hash
    material. Raised BEFORE any row is written, so a wrong selection fails
    visibly instead of launching a job against nothing (or, worse, against
    transcribed text)."""


class JobRefused(Exception):
    """A submit refused by policy -- the concurrency cap, or a duplicate of a
    job that is already running or has already reached a terminal answer. The
    message carries the prior verdict so the model reads the settled result
    instead of relaunching."""


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Liveness -- advisory flock, PID-free.
# ---------------------------------------------------------------------------

# The supervisor keeps its lock fd open for its whole life; a module global so
# it is never garbage-collected (which would release the lock early).
_LOCK_FD = None


def _acquire_lock(lock_path):
    """Held by the supervisor for its entire life. Blocking LOCK_EX: the only
    contender for this path is a stale holder, and there should be none."""
    global _LOCK_FD
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX)
    _LOCK_FD = fd
    return fd


def is_alive(lock_path):
    """True iff SOME process still holds the job's lock -- i.e. the job is
    alive. Needs no PID: we try to take the lock non-blocking; success means
    nobody holds it (dead), EWOULDBLOCK means someone does (alive). A missing
    lockfile is 'dead' (nothing to hold it)."""
    if not lock_path or not os.path.exists(lock_path):
        return False
    try:
        fd = os.open(lock_path, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except (BlockingIOError, OSError):
        return True
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

def _job_loot_paths(session_id, job_id, name):
    """(host_path, container_path) for a file in this job's working dir under
    the loot bind mount -- same two-views-of-one-directory as agent._loot_paths,
    under session-<sid>/jobs/job-<jid>/. The container reads/writes these; they
    are transient (reset.sh --attacker wipes loot), but the settled answer
    persists in job_results regardless."""
    rel = f"session-{session_id}/jobs/job-{job_id}/{name}"
    host = os.path.join(redteam_exec.LOOT_HOST_DIR, rel)
    os.makedirs(os.path.dirname(host), exist_ok=True)
    return host, f"{redteam_exec.LOOT_CONTAINER_DIR}/{rel}"


def _lock_path(job_id):
    return os.path.join(JOBS_STATE_DIR, f"job-{job_id}.lock")


# ---------------------------------------------------------------------------
# Crack job type -- john with harness-set parameters.
# ---------------------------------------------------------------------------

# john --show's trailing summary, e.g. "2 password hashes cracked, 0 left" or
# "0 password hashes cracked, 2 left" (singular "hash" for 1).
_SHOW_SUMMARY_RE = re.compile(r"(\d+)\s+password hash(?:es)? cracked", re.IGNORECASE)
# john can't load the hashes at all -- a wrong --format, or garbage material.
# This is an input/selection problem the model can fix and retry, NOT a settled
# answer, so it must read as such.
_LOAD_ERROR_RE = re.compile(
    r"No password hashes loaded|No known format|Unknown ciphertext format|"
    r"No password hashes left to crack",
    re.IGNORECASE,
)


class CrackJobType:
    job_type = "crack"

    @staticmethod
    def validate_and_extract(loot_row, selector):
        """Turn a stored loot artifact + a selector into the exact hash lines
        john will see. Raises JobInputError (visibly, before any job row) if the
        selection yields nothing usable -- the inverse also matters: a silent
        empty extraction would let the agent conclude a credential path is dead
        when it never really tried.

        selector:
          format   (str, required)  john format name, e.g. 'sha512crypt',
                                     'Raw-MD5', 'bcrypt'. Not validated here
                                     (john validates at run time); a wrong
                                     format surfaces as a visible load error.
          lines    ('all' | [int])  1-based line numbers of the loot file to
                                     take hashes from; default 'all'.
          field    (int | None)     1-based ':'-delimited field holding the
                                     hash, for a dump like 'user:hash:...' or
                                     /etc/shadow; None means the whole line.
          delimiter(str)            field separator, default ':'.
        """
        fmt = (selector or {}).get("format")
        if not fmt or not isinstance(fmt, str):
            raise JobInputError(
                "selector.format is required -- the john hash format of the material "
                "(e.g. 'sha512crypt', 'Raw-MD5', 'bcrypt')"
            )
        path = loot_row["path"]
        # loot.path is stored as the container view (/loot/...) for gated-tool
        # loot and as a host path elsewhere; resolve to a readable host path.
        host_path = _loot_host_path(path)
        if not host_path or not os.path.isfile(host_path):
            raise JobInputError(
                f"loot #{loot_row['id']} has no readable file on disk at {path!r} "
                "-- nothing to extract hashes from (it may have been reset, "
                "or this loot row is a stdout-only summary)"
            )
        with open(host_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.read().splitlines()

        want = (selector or {}).get("lines", "all")
        if want == "all" or want is None:
            chosen = all_lines
        else:
            if not isinstance(want, list) or not all(isinstance(n, int) for n in want):
                raise JobInputError("selector.lines must be 'all' or a list of 1-based line numbers")
            chosen = []
            for n in want:
                if 1 <= n <= len(all_lines):
                    chosen.append(all_lines[n - 1])
            if not chosen:
                raise JobInputError(
                    f"selector.lines {want} selected no lines -- loot #{loot_row['id']} "
                    f"has {len(all_lines)} line(s)"
                )

        field = (selector or {}).get("field")
        delim = (selector or {}).get("delimiter", ":")
        tokens = []
        for line in chosen:
            line = line.strip()
            if not line:
                continue
            if field is not None:
                parts = line.split(delim)
                if not isinstance(field, int) or field < 1 or field > len(parts):
                    continue
                tok = parts[field - 1].strip()
            else:
                tok = line
            if tok:
                tokens.append(tok)

        if not tokens:
            raise JobInputError(
                f"no usable hash material after applying the selector to loot "
                f"#{loot_row['id']} (lines={want}, field={field}) -- check the "
                "line numbers and field index against the actual dump"
            )
        return tokens

    @staticmethod
    def build_argv(job_row, selector, hashfile_ctr, potfile_ctr):
        fmt = selector["format"]
        wordlist = selector.get("wordlist_ctr") or DEFAULT_WORDLIST_CTR
        # --pot is a fresh PER-JOB potfile: every entry in it was produced by
        # THIS run, so produced_new_information is unambiguous and a prior
        # job's cracked password can never masquerade as this one's. --session
        # keeps john's .rec/.log files from colliding across jobs.
        return [
            "john",
            f"--format={fmt}",
            f"--wordlist={wordlist}",
            f"--pot={potfile_ctr}",
            f"--session=job{job_row['id']}",
            hashfile_ctr,
        ]

    @staticmethod
    def parse_output(total_hashes, loot_id, wordlist, show_output, stream_text, exec_result):
        """Decide the SETTLED outcome from john's real output. Exit code does
        NOT tell you this: john exits 0 on a clean run whether it cracked
        everything or nothing, and non-zero on a kill that may still have
        cracked some. So the source of truth is `john --show` against the
        per-job potfile (what actually landed), cross-checked with the run's
        end-state (completed / killed / load-error).

        Returns the job_results payload."""
        load_error = bool(_LOAD_ERROR_RE.search(show_output) or _LOAD_ERROR_RE.search(stream_text))
        m = _SHOW_SUMMARY_RE.search(show_output)
        cracked_n = int(m.group(1)) if m else 0

        recovered = []
        if cracked_n:
            for line in show_output.splitlines():
                line = line.rstrip("\n")
                if not line or _SHOW_SUMMARY_RE.search(line):
                    continue
                if ":" in line:
                    left, right = line.split(":", 1)
                    recovered.append({"id": left, "plaintext": right})

        killed = bool(exec_result.timed_out or exec_result.kill_reason)
        completed = "Session completed" in stream_text

        if cracked_n >= 1:
            outcome = "cracked"
            produced = 1
            sample = ", ".join(f"{r['id']}={r['plaintext']}" for r in recovered[:3])
            verdict = (
                f"CRACKED {cracked_n}/{total_hashes} hash(es) from loot #{loot_id} "
                f"using {os.path.basename(wordlist)}: {sample}"
                f"{' ...' if len(recovered) > 3 else ''}. Recovered credential(s) "
                "recorded to session state. Terminal -- do not relaunch this crack."
            )
        elif load_error and not completed:
            # An input/selection problem, not a settled answer about the
            # hashes -- the model can fix the format/selection and try again.
            outcome = "interrupted"
            produced = 0
            verdict = (
                f"Crack did NOT run against loot #{loot_id}: john could not load the "
                f"material (likely a wrong selector.format). No answer about whether "
                "these hashes are crackable -- fix the format/selection and resubmit."
            )
        elif completed and not killed:
            outcome = "exhausted"
            produced = 1
            verdict = (
                f"Wordlist {os.path.basename(wordlist)} EXHAUSTED against {total_hashes} "
                f"hash(es) from loot #{loot_id}; 0 recovered. This wordlist does not crack "
                "these hashes -- do not relaunch the same crack. A different wordlist or "
                "attack mode would be a different job."
            )
        else:
            outcome = "interrupted"
            produced = 0
            why = exec_result.kill_reason or ("timed out" if exec_result.timed_out else "ended without completing")
            verdict = (
                f"Crack against loot #{loot_id} did not reach a settled answer ({why}); "
                f"{cracked_n} recovered so far. Not terminal -- may be relaunched."
            )

        return {
            "outcome": outcome,
            "produced_new_information": produced,
            "terminal_verdict": verdict,
            "recovered": recovered,
            "detail": {
                "total_hashes": total_hashes,
                "cracked": cracked_n,
                "wordlist": wordlist,
                "kill_reason": exec_result.kill_reason,
                "elapsed_s": round(exec_result.elapsed_s, 1),
            },
        }


JOB_TYPES = {"crack": CrackJobType}


def _loot_host_path(path):
    """A loot row's stored `path` -> a readable HOST path. Gated-tool loot is
    stored as the container view (/loot/...); translate that back to the host
    bind-mount dir. A path that's already a host path is returned as-is."""
    if not path:
        return None
    if path.startswith(redteam_exec.LOOT_CONTAINER_DIR + "/"):
        rel = path[len(redteam_exec.LOOT_CONTAINER_DIR) + 1:]
        return os.path.join(redteam_exec.LOOT_HOST_DIR, rel)
    return path


def _dedup_key(job_type, source_loot_id, tokens):
    """Identifies a crack by its MATERIAL, not the selector phrasing: the same
    hashes from the same loot dedup to the same key however they were picked.
    A second crack against this key is refused while one is running or has
    already reached a terminal answer (see submit())."""
    norm = "\n".join(sorted(t.strip() for t in tokens))
    h = hashlib.sha256(f"{job_type}\x00{source_loot_id}\x00{norm}".encode()).hexdigest()
    return h[:32]


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------

def submit(conn, session_id, job_type, source_loot_id, selector):
    """Launch a background job. Raises JobInputError (bad/empty selection) or
    JobRefused (cap / duplicate) -- both BEFORE anything irreversible. Returns
    a dict describing the launched job, for the tool result."""
    if job_type not in JOB_TYPES:
        raise JobInputError(f"unknown job_type {job_type!r}; known: {sorted(JOB_TYPES)}")
    jt = JOB_TYPES[job_type]

    # Reconcile crashed supervisors first, so the cap/dup checks below see
    # reality, not rows a dead supervisor left marked 'running'.
    reap(conn)

    loot_row = conn.execute(
        "SELECT id, target, path, pending_action_id FROM loot WHERE id=? AND session_id=?",
        (source_loot_id, session_id),
    ).fetchone()
    if loot_row is None:
        raise JobInputError(
            f"no loot #{source_loot_id} in this session -- job input must come from a "
            "stored loot artifact (see get_loot), not supplied text"
        )

    tokens = jt.validate_and_extract(loot_row, selector)   # raises JobInputError on a bad selection
    dedup_key = _dedup_key(job_type, source_loot_id, tokens)

    dup = conn.execute(
        "SELECT j.id, j.status, r.terminal_verdict FROM jobs j "
        "LEFT JOIN job_results r ON r.job_id = j.id "
        "WHERE j.dedup_key=? AND j.status IN ('running','completed') ORDER BY j.id DESC LIMIT 1",
        (dedup_key,),
    ).fetchone()
    if dup is not None:
        if dup["status"] == "running":
            raise JobRefused(
                f"a crack against this exact material is already running (job #{dup['id']}); "
                "wait for it to finish rather than launching a second"
            )
        raise JobRefused(
            f"this material was already cracked-or-exhausted by job #{dup['id']} and the "
            f"answer is settled: {dup['terminal_verdict']!r}. Not relaunching."
        )

    running = conn.execute("SELECT COUNT(*) n FROM jobs WHERE status='running'").fetchone()["n"]
    if running >= MAX_CONCURRENT_JOBS:
        raise JobRefused(
            f"at the background-job concurrency cap ({running}/{MAX_CONCURRENT_JOBS}); "
            "the host is also serving local models -- wait for a running job to finish"
        )

    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO jobs (session_id, job_type, status, dedup_key, source_loot_id, "
        "selector_json, lock_path, created) VALUES (?,?,?,?,?,?,?,?)",
        (session_id, job_type, "running", dedup_key, source_loot_id,
         json.dumps(selector), "", ts),
    )
    job_id = cur.lastrowid

    # Now that we have the id, lay down the files and the paths keyed by it.
    hashfile_host, hashfile_ctr = _job_loot_paths(session_id, job_id, "hashes.txt")
    stream_host, _ = _job_loot_paths(session_id, job_id, "crack.stream.log")
    with open(hashfile_host, "w", encoding="utf-8") as f:
        f.write("\n".join(tokens) + "\n")
    lock_path = _lock_path(job_id)
    container_pidfile = redteam_exec._to_container_path(stream_host)
    container_pidfile = (container_pidfile + ".pid") if container_pidfile else None
    conn.execute(
        "UPDATE jobs SET lock_path=?, stream_path=?, container_pidfile=? WHERE id=?",
        (lock_path, stream_host, container_pidfile, job_id),
    )
    conn.commit()

    _spawn_supervisor(job_id)
    return {
        "job_id": job_id,
        "job_type": job_type,
        "status": "running",
        "source_loot_id": source_loot_id,
        "hash_count": len(tokens),
        "note": (
            f"background {job_type} job #{job_id} launched against {len(tokens)} hash(es) "
            f"from loot #{source_loot_id}. It runs detached -- keep working; the settled "
            "result will appear on a later turn (or check with list_jobs/get_job). Do not "
            "relaunch the same material."
        ),
    }


def _spawn_supervisor(job_id):
    """Detached, parent-independent. start_new_session (setsid) + DEVNULL stdin
    + stdio redirected to a log file means killing the agent does NOT kill the
    supervisor -- the job survives the parent, exactly what adoption needs."""
    os.makedirs(JOBS_STATE_DIR, exist_ok=True)
    log = open(os.path.join(JOBS_STATE_DIR, f"job-{job_id}.supervisor.log"), "ab")
    subprocess.Popen(
        [sys.executable, _THIS_FILE, "run", str(job_id)],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True, close_fds=True,
    )


# ---------------------------------------------------------------------------
# Supervisor -- the detached process that actually runs the job.
# ---------------------------------------------------------------------------

def _connect():
    import sqlite3
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def run_supervisor(job_id):
    conn = _connect()
    job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if job is None or job["status"] != "running":
        return
    _acquire_lock(job["lock_path"])   # held for the whole run; freed on exit/death by the kernel
    conn.execute("UPDATE jobs SET launched_at=? WHERE id=?", (now_iso(), job_id))
    conn.commit()

    try:
        if job["job_type"] == "crack":
            _run_crack(conn, job)
        elif job["job_type"] == "promoted":
            _monitor_promoted(conn, job)
        else:
            _finalize(conn, job_id, "interrupted", 0,
                      f"unknown job_type {job['job_type']!r}", {}, None, [])
    except Exception as e:  # noqa: BLE001 -- a supervisor crash must still leave a settled row
        _finalize(conn, job_id, "interrupted", 0,
                  f"background job crashed before finishing: {e}", {"error": str(e)}, None, [])


def _run_crack(conn, job):
    selector = json.loads(job["selector_json"] or "{}")
    session_id = job["session_id"]
    job_id = job["id"]
    loot_row = conn.execute("SELECT id, target, path FROM loot WHERE id=?", (job["source_loot_id"],)).fetchone()

    hashfile_host, hashfile_ctr = _job_loot_paths(session_id, job_id, "hashes.txt")
    potfile_host, potfile_ctr = _job_loot_paths(session_id, job_id, "john.pot")
    with open(hashfile_host, "r", encoding="utf-8", errors="replace") as f:
        total_hashes = len([ln for ln in f.read().splitlines() if ln.strip()])

    argv = CrackJobType.build_argv(job, selector, hashfile_ctr, potfile_ctr)
    t0 = time.monotonic()
    # idle_timeout_s=0 disables non-progress kill (a crack is legitimately
    # quiet); max_wall_s is the only bound. Streams to the job's loot file, so
    # a killed run still leaves everything it wrote.
    result = redteam_exec.run(argv, stream_path=job["stream_path"],
                              idle_timeout_s=0, max_wall_s=CRACK_MAX_WALL_S,
                              max_output_chars=24000)
    compute_s = time.monotonic() - t0

    # Source of truth for what actually cracked: --show against the per-job pot.
    wordlist = selector.get("wordlist_ctr") or DEFAULT_WORDLIST_CTR
    show = redteam_exec.run(
        ["john", f"--format={selector['format']}", f"--pot={potfile_ctr}", "--show", hashfile_ctr],
        timeout_s=60,
    )
    try:
        with open(job["stream_path"], "r", encoding="utf-8", errors="replace") as f:
            stream_text = f.read()
    except OSError:
        stream_text = result.stdout or ""

    parsed = CrackJobType.parse_output(total_hashes, loot_row["id"] if loot_row else job["source_loot_id"],
                                       wordlist, show.stdout or "", stream_text, result)
    _finalize(conn, job_id, parsed["outcome"], parsed["produced_new_information"],
              parsed["terminal_verdict"], parsed["detail"], potfile_host, parsed["recovered"],
              compute_s=compute_s, loot_target=(loot_row["target"] if loot_row else None),
              source_pending_action_id=_loot_pending_action_id(conn, job["source_loot_id"]))


def _monitor_promoted(conn, job):
    """Monitor an ALREADY-RUNNING in-container process that a foreground tool
    call was promoted into (see agent.execute_pending_action). We did not
    launch it and must not relaunch it -- we wait for it to exit (polling the
    pidfile the foreground wrapper already wrote), then finalize from the
    stream file it is still writing. Output survives because it was streaming
    to loot from the start."""
    job_id = job["id"]
    ctr_pidfile = job["container_pidfile"]
    pid = _read_container_pid(ctr_pidfile)
    t0 = time.monotonic()
    last_bytes = _stream_size(job["stream_path"])
    last_progress = t0
    poll = max(1, redteam_exec.HANG_POLICY["poll_interval_s"])
    kill_reason = None
    while pid and _container_pid_alive(pid):
        time.sleep(poll)
        now = time.monotonic()
        seen = _stream_size(job["stream_path"])
        if seen != last_bytes:
            last_bytes, last_progress = seen, now
        if (now - t0) >= CRACK_MAX_WALL_S:
            redteam_exec._kill_remote(ctr_pidfile)
            kill_reason = "wall"
            break
    compute_s = time.monotonic() - t0
    try:
        with open(job["stream_path"], "r", encoding="utf-8", errors="replace") as f:
            stream_text = f.read()
    except OSError:
        stream_text = ""
    outcome = "interrupted" if kill_reason else "completed"
    produced = 1 if (not kill_reason and stream_text.strip()) else 0
    verdict = (
        f"Promoted foreground action (pending_action #{job['promoted_from_pending_action_id']}) "
        + ("hit the wall backstop and was stopped." if kill_reason
           else "finished in the background; its full output is in loot and on the pending action.")
    )
    # Mirror the settled output back onto the originating pending action so the
    # existing get_pending_actions path shows it too.
    if job["promoted_from_pending_action_id"]:
        conn.execute(
            "UPDATE pending_actions SET result_json=? WHERE id=?",
            (json.dumps({"promoted_job": job_id, "stdout": stream_text[:24000],
                         "kill_reason": kill_reason, "elapsed_s": round(compute_s, 1)}),
             job["promoted_from_pending_action_id"]),
        )
    _finalize(conn, job_id, outcome, produced, verdict,
              {"kill_reason": kill_reason, "elapsed_s": round(compute_s, 1)},
              job["stream_path"], [], compute_s=compute_s)


def _finalize(conn, job_id, outcome, produced, verdict, detail, result_path, recovered,
              compute_s=None, loot_target=None, source_pending_action_id=None):
    """Write the system-of-record row and flip the job terminal. The ONE place
    a crack's recovered credentials enter state_credentials -- a side effect of
    the harness finalizing, never a model tool -- so a win claiming a crack has
    a harness-written record behind it and can't be conjured from prose."""
    status = "killed" if outcome == "interrupted" else "completed"
    conn.execute(
        "INSERT INTO job_results (job_id, outcome, produced_new_information, terminal_verdict, "
        "detail_json, result_path, created) VALUES (?,?,?,?,?,?,?)",
        (job_id, outcome, int(produced), verdict, json.dumps(detail),
         result_path, now_iso()),
    )
    for r in recovered or []:
        conn.execute(
            "INSERT INTO state_credentials (session_id, target, username, password, status, "
            "source, provenance_id, created) SELECT session_id, ?, ?, ?, 'confirmed', ?, ?, ? "
            "FROM jobs WHERE id=?",
            (loot_target or "(unknown)", r.get("id") or "?", r.get("plaintext") or "",
             f"crack:job{job_id}", source_pending_action_id, now_iso(), job_id),
        )
    conn.execute(
        "UPDATE jobs SET status=?, finished_at=?, compute_s=? WHERE id=?",
        (status, now_iso(), compute_s, job_id),
    )
    conn.commit()


def _loot_pending_action_id(conn, loot_id):
    row = conn.execute("SELECT pending_action_id FROM loot WHERE id=?", (loot_id,)).fetchone()
    return row["pending_action_id"] if row else None


# --- in-container process helpers (promoted jobs only) ---------------------

def _read_container_pid(ctr_pidfile):
    if not ctr_pidfile:
        return None
    r = redteam_exec.run(["cat", ctr_pidfile], timeout_s=10)
    txt = (r.stdout or "").strip()
    return txt if txt.isdigit() else None


def _container_pid_alive(pid):
    r = redteam_exec.run(["sh", "-c", f"kill -0 {int(pid)} 2>/dev/null && echo up || echo down"], timeout_s=10)
    return "up" in (r.stdout or "")


def _stream_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# ---------------------------------------------------------------------------
# Reaper
# ---------------------------------------------------------------------------

def reap(conn, kill_orphans=False):
    """Reconcile 'running' jobs against reality, cheaply (a flock probe per
    job; no docker exec unless something actually needs killing/finalizing).

    - Lock free + already has a result  -> just ensure status is terminal
      (the normal completion; the supervisor set it before releasing).
    - Lock free + no result + past grace -> the supervisor died mid-run.
      Mark it killed with an 'interrupted' record (streamed output survives on
      disk; not terminal, so it may be relaunched).
    - Lock held (alive) + kill_orphans + over the wall backstop -> a genuine
      orphan competing for the box: kill the in-container process via its
      pidfile and mark it killed.

    kill_orphans is off in the hot path (kept free) and on for startup/reset."""
    reaped = 0
    rows = conn.execute(
        "SELECT j.id, j.lock_path, j.container_pidfile, j.created, j.launched_at, "
        "(SELECT COUNT(*) FROM job_results r WHERE r.job_id=j.id) AS has_result "
        "FROM jobs j WHERE j.status='running'"
    ).fetchall()
    for j in rows:
        alive = is_alive(j["lock_path"])
        if alive:
            if kill_orphans and _over_wall(j):
                redteam_exec._kill_remote(j["container_pidfile"])
                _mark_killed(conn, j["id"], "orphan exceeded the wall backstop and was reaped")
                reaped += 1
            continue
        # Lock free -> supervisor is gone.
        if j["has_result"]:
            conn.execute(
                "UPDATE jobs SET status=COALESCE((SELECT CASE WHEN outcome='interrupted' THEN 'killed' "
                "ELSE 'completed' END FROM job_results WHERE job_id=?), 'completed'), "
                "finished_at=COALESCE(finished_at, ?) WHERE id=? AND status='running'",
                (j["id"], now_iso(), j["id"]),
            )
            conn.commit()
            continue
        if _older_than(j["created"], STARTUP_GRACE_S):
            _mark_killed(conn, j["id"], "supervisor exited before finalizing; streamed output "
                                         "preserved in loot -- not terminal, may be relaunched")
            reaped += 1
    return reaped


def _mark_killed(conn, job_id, why):
    conn.execute(
        "INSERT INTO job_results (job_id, outcome, produced_new_information, terminal_verdict, "
        "detail_json, result_path, created) VALUES (?, 'interrupted', 0, ?, ?, NULL, ?)",
        (job_id, why, json.dumps({"reaped": True}), now_iso()),
    )
    conn.execute("UPDATE jobs SET status='killed', finished_at=? WHERE id=?", (now_iso(), job_id))
    conn.commit()


def _over_wall(job_row):
    base = job_row["launched_at"] or job_row["created"]
    return _older_than(base, CRACK_MAX_WALL_S + 60)


def _older_than(ts, seconds):
    if not ts:
        return False
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - t).total_seconds() > seconds


# ---------------------------------------------------------------------------
# Surfacing -- to the agent, across chunks (free) and as a push on completion.
# ---------------------------------------------------------------------------

def render_jobs_block(conn, session_id):
    """Compact standing view of this session's jobs for _persistent_context_block
    -- visible at the start of EVERY chunk with no tool call, so a job launched
    in one chunk is never lost to a later one. Returns '' when there's nothing."""
    rows = conn.execute(
        "SELECT j.id, j.job_type, j.status, j.source_loot_id, r.outcome, r.terminal_verdict "
        "FROM jobs j LEFT JOIN job_results r ON r.job_id=j.id "
        "WHERE j.session_id=? ORDER BY j.id DESC LIMIT 12",
        (session_id,),
    ).fetchall()
    if not rows:
        return ""
    lines = []
    for j in rows:
        if j["status"] == "running":
            lines.append(f"  - job #{j['id']} ({j['job_type']}, loot #{j['source_loot_id']}): RUNNING "
                         "-- do not relaunch; its result will appear when done")
        else:
            lines.append(f"  - job #{j['id']} ({j['job_type']}): {j['outcome'] or j['status']} -- "
                         f"{j['terminal_verdict'] or ''}")
    return "Background jobs (detached; launched via submit_job):\n" + "\n".join(lines)


def drain_completions(conn, session_id):
    """Terminal jobs not yet pushed to the model -- returned once, then marked
    surfaced. This is the unprompted completion notice: _progress_wrapper
    appends it to the next tool result (no dedicated iteration), so a job that
    finished mid-chunk is noticed on the agent's very next turn."""
    rows = conn.execute(
        "SELECT j.id, j.job_type, r.outcome, r.terminal_verdict "
        "FROM jobs j JOIN job_results r ON r.job_id=j.id "
        "WHERE j.session_id=? AND j.status IN ('completed','killed') AND j.surfaced=0 "
        "ORDER BY j.id",
        (session_id,),
    ).fetchall()
    if not rows:
        return ""
    ids = [r["id"] for r in rows]
    conn.executemany("UPDATE jobs SET surfaced=1 WHERE id=?", [(i,) for i in ids])
    conn.commit()
    notices = [f"background job #{r['id']} ({r['job_type']}) {r['outcome']}: {r['terminal_verdict']}"
               for r in rows]
    return "\n\n[BACKGROUND JOB COMPLETED]\n" + "\n".join(notices)


# ---------------------------------------------------------------------------
# Read-only views for get_job / list_jobs tools (pure SELECTs -- no process,
# nearly free, so checking status never costs the agent a real iteration).
# ---------------------------------------------------------------------------

def list_jobs(conn, session_id):
    reap(conn)
    rows = conn.execute(
        "SELECT j.id, j.job_type, j.status, j.source_loot_id, j.launched_at, j.finished_at, "
        "j.compute_s, r.outcome, r.produced_new_information, r.terminal_verdict "
        "FROM jobs j LEFT JOIN job_results r ON r.job_id=j.id "
        "WHERE j.session_id=? ORDER BY j.id",
        (session_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_job(conn, session_id, job_id):
    reap(conn)
    row = conn.execute(
        "SELECT j.*, r.outcome, r.produced_new_information, r.terminal_verdict, r.detail_json "
        "FROM jobs j LEFT JOIN job_results r ON r.job_id=j.id "
        "WHERE j.id=? AND j.session_id=?",
        (job_id, session_id),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Promotion support (called by agent.execute_pending_action via a callback).
# ---------------------------------------------------------------------------

def run_promotable_shell(conn, session_id, pending_action_id, command, max_wall_s):
    """shell_exec under promotion: launch the command DETACHED-TO-FILE inside
    soc-attacker (redirected to a loot file, backgrounded, self-bounded by an
    in-container `timeout -s KILL`), then watch it for PROMOTE_AFTER_S. Because
    it writes to a file rather than a docker-exec stdout pipe, it can be handed
    off without a SIGPIPE killing it -- which the streaming monitored path
    cannot do.

    Returns (result_dict, loot_ctr, promoted_job_id_or_None):
      - finishes within the window  -> its output, promoted_job_id None (the
        caller treats it exactly like a normal foreground execution);
      - still running and producing output at the threshold -> promoted to a
        background job, promoted_job_id set (the caller records that and moves
        on; the job's supervisor finalizes it later)."""
    ts = int(time.time())
    rel = f"session-{session_id}/shell-promote-{ts}.log"
    stream_host = os.path.join(redteam_exec.LOOT_HOST_DIR, rel)
    os.makedirs(os.path.dirname(stream_host), exist_ok=True)
    stream_ctr = f"{redteam_exec.LOOT_CONTAINER_DIR}/{rel}"
    pid_ctr = stream_ctr + ".pid"
    wrapper = (
        f"mkdir -p {shlex.quote(os.path.dirname(pid_ctr))}; "
        f"setsid timeout -s KILL {int(max_wall_s)}s bash -lc {shlex.quote(command)} "
        f"> {shlex.quote(stream_ctr)} 2>&1 & echo $! > {shlex.quote(pid_ctr)}"
    )
    redteam_exec.run(["sh", "-c", wrapper], timeout_s=30)   # backgrounded -> returns at once
    pid = _read_container_pid(pid_ctr)
    t0 = time.monotonic()
    last_bytes, last_progress = 0, t0
    poll = max(1, redteam_exec.HANG_POLICY["poll_interval_s"])
    while pid and _container_pid_alive(pid):
        time.sleep(poll)
        now = time.monotonic()
        seen = _stream_size(stream_host)
        if seen != last_bytes:
            last_bytes, last_progress = seen, now
        # Promote only if it crossed the threshold AND is actually producing
        # output (still making progress) -- not a wedged call, which idle
        # detection would handle instead.
        if PROMOTE_AFTER_S and (now - t0) >= PROMOTE_AFTER_S and seen > 0:
            jid = adopt_promoted(conn, session_id, pending_action_id, stream_host, pid_ctr)
            return (
                {"exit_code": None, "timed_out": False, "stdout": "", "stderr": "",
                 "elapsed_s": round(now - t0, 1), "promoted_job": jid,
                 "note": f"still running after {int(now - t0)}s -- promoted to background job "
                         f"#{jid}; its result will arrive on a later turn"},
                stream_ctr, jid,
            )
    try:
        with open(stream_host, "r", encoding="utf-8", errors="replace") as f:
            out = f.read()
    except OSError:
        out = ""
    return (
        {"exit_code": None, "timed_out": False, "stdout": out[:24000], "stderr": "",
         "elapsed_s": round(time.monotonic() - t0, 1)},
        stream_ctr, None,
    )


def adopt_promoted(conn, session_id, pending_action_id, stream_path, container_pidfile):
    """Record a jobs row for an already-running in-container process a
    foreground call was promoted into, and spawn a MONITOR-only supervisor for
    it. Returns the new job id. The process keeps running untouched; only the
    host-side wait is handed off, so the turn is freed."""
    ts = now_iso()
    cur = conn.execute(
        "INSERT INTO jobs (session_id, job_type, status, promoted_from_pending_action_id, "
        "lock_path, stream_path, container_pidfile, launched_at, created) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (session_id, "promoted", "running", pending_action_id, "",
         stream_path, container_pidfile, ts, ts),
    )
    job_id = cur.lastrowid
    conn.execute("UPDATE jobs SET lock_path=? WHERE id=?", (_lock_path(job_id), job_id))
    conn.commit()
    _spawn_supervisor(job_id)
    return job_id


# ---------------------------------------------------------------------------
# CLI -- the supervisor entrypoint and a reaper for reset.sh.
# ---------------------------------------------------------------------------

def main(argv):
    if not argv:
        print("usage: jobs.py {run <job_id> | reap [--kill-orphans]}", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "run":
        run_supervisor(int(argv[1]))
        return 0
    if cmd == "reap":
        conn = _connect()
        n = reap(conn, kill_orphans="--kill-orphans" in argv)
        print(f"reaped {n} job(s)")
        return 0
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
