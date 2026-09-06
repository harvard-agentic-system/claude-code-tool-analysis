#!/usr/bin/env python3
"""
cc-toolstat - audit your Claude Code tool usage.

Parses every session transcript under your Claude Code data directory and emits:
  * tool_calls.parquet   one row per tool call  (CSV fallback if pyarrow is absent)
  * web_urls.parquet     one row per URL searched or fetched
  * dashboard.html       a self-contained interactive dashboard
  * report.txt           a plain-text analysis

Requires only the Python standard library. Install pyarrow for parquet output.

    python3 cc_toolstat.py                 # analyse ~/.claude, write ./cc-toolstat-out
    python3 cc_toolstat.py --open          # ...and open the dashboard
    python3 cc_toolstat.py --redact        # strip paths, commands, queries and URLs
    python3 cc_toolstat.py --since 2026-08-01 --out ~/audit

MIT licensed. Reads local files only; sends nothing anywhere.
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

__version__ = "1.0.0"

# ---------------------------------------------------------------- taxonomy ---

CATEGORY = {
    "Read": "file_read", "NotebookRead": "file_read",
    "Write": "file_write", "Edit": "file_write", "MultiEdit": "file_write",
    "NotebookEdit": "file_write",
    "Grep": "search", "Glob": "search", "LS": "search", "ToolSearch": "search",
    "SearchSkills": "search", "SearchPlugins": "search", "ListSkills": "search",
    "ListPlugins": "search", "ListMcpResourcesTool": "search",
    "Bash": "shell", "BashOutput": "shell", "KillBash": "shell", "KillShell": "shell",
    "Monitor": "shell",
    "WebSearch": "web", "WebFetch": "web",
    "Agent": "agent", "Task": "agent", "SendMessage": "agent", "ListAgents": "agent",
    "TaskOutput": "agent", "TaskStop": "agent", "Workflow": "agent",
    "TodoWrite": "planning", "ExitPlanMode": "planning", "EnterPlanMode": "planning",
    "AskUserQuestion": "user_io", "SendUserFile": "user_io", "PushNotification": "user_io",
    "Artifact": "output", "StructuredOutput": "output", "ReportFindings": "output",
    "Skill": "skill", "SlashCommand": "skill", "SuggestSkills": "skill",
    "EnterWorktree": "vcs", "ExitWorktree": "vcs",
    "CronCreate": "schedule", "CronList": "schedule", "CronDelete": "schedule",
    "ScheduleWakeup": "schedule",
}

# Ordered; first match wins. Tuned against real transcripts.
ERROR_RULES = [
    # -- the operator's own guardrails ------------------------------------
    ("hook_gate",        r"\[[^\]]*(?:Gate|Guard|Policy|Checkpoint)\]|"
                         r"hook (?:blocked|denied|rejected)|blocked by (?:a |the )?\S+ hook"),
    ("hook_timeout",     r"(?:Pre|Post)ToolUse hook did not respond before its timeout"),
    ("policy_blocked",   r"denied by the Claude Code auto mode classifier|"
                         r"<tool_use_error>Blocked:|^Blocked:\s|permission (?:denied|rule)"),
    ("user_rejected",    r"user (?:doesn'?t want|rejected|denied|declined)|\[Request interrupted"),
    ("worktree_isolated", r"session is isolated in the worktree"),
    ("worktree_dirty",   r"Worktree has \d+ commit"),
    # -- platform / harness limits ----------------------------------------
    ("file_too_large",   r"exceeds maximum allowed (?:tokens|size)|maxContentLength size of"),
    ("concurrency_limit", r"Concurrent subagent limit reached|rate limit|too many requests"),
    ("model_unavailable", r"temporarily unavailable|overloaded_error|is currently overloaded"),
    ("permission_infra", r"Tool permission request failed"),
    # -- the agent got it wrong -------------------------------------------
    ("schema_invalid",   r"Output does not match required schema"),
    ("script_invalid",   r"Invalid workflow script|Script parse error"),
    ("edit_ambiguous",   r"Found \d+ matches of the string to replace"),
    ("noop_edit",        r"old_string and new_string are exactly the same"),
    ("stale_read",       r"has not been read|has been (?:modified|unexpectedly)|"
                         r"File has been modified since read"),
    ("no_match",         r"String to replace not found|not found in file|"
                         r"No (?:files )?found|no matches"),
    ("file_not_found",   r"no such file or directory|ENOENT|does not exist|EISDIR|cannot access"),
    ("bad_input",        r"InputValidationError|invalid (?:input|argument|parameter)|"
                         r"is required|unrecognized"),
    # -- the command itself failed ----------------------------------------
    ("timeout",          r"Command timed out|timed out after|ETIMEDOUT|exceeded .*timeout"),
    ("fetch_blocked",    r"unable to fetch from|robots\.txt|blocked by the site"),
    ("network",          r"ECONNREFUSED|ENOTFOUND|connection (?:refused|reset)|"
                         r"Could not resolve|\bSSL\b|\b50[234]\b"),
    ("nonzero_exit",     r"\bExit code \d+"),
]
ERROR_RX = [(k, re.compile(p, re.I | re.M)) for k, p in ERROR_RULES]

ERROR_GROUP = {
    "hook_gate": "blocked_by_policy", "policy_blocked": "blocked_by_policy",
    "user_rejected": "blocked_by_policy", "worktree_isolated": "blocked_by_policy",
    "worktree_dirty": "blocked_by_policy",
    "hook_timeout": "hook_infra", "permission_infra": "hook_infra",
    "file_too_large": "infra_limit", "concurrency_limit": "infra_limit",
    "model_unavailable": "infra_limit",
    "schema_invalid": "agent_mistake", "script_invalid": "agent_mistake",
    "edit_ambiguous": "agent_mistake", "noop_edit": "agent_mistake",
    "stale_read": "agent_mistake", "no_match": "agent_mistake",
    "file_not_found": "agent_mistake", "bad_input": "agent_mistake",
    "nonzero_exit": "command_failed", "timeout": "command_failed",
    "network": "command_failed", "fetch_blocked": "command_failed",
}
# Groups that are friction but not a tool defect.
NOT_REAL = ("blocked_by_policy", "hook_infra")

# ------------------------------------------------------------ bash parsing ---

HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
SPLIT = re.compile(r"\n|&&|\|\||;|\|")
TOKEN = re.compile(
    r"^\s*(?:(?:sudo|time|nohup|command|exec|xargs)\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*([\w./+-]+)")
SHELL_KW = {
    "if", "then", "else", "elif", "fi", "for", "do", "done", "while", "until", "case",
    "esac", "in", "function", "cd", "set", "export", "local", "return", "source", ".",
    "eval", "trap", "shift", "read", "declare", "unset", "alias",
    "break", "continue", "fg", "bg",
}


def parse_bash(cmd):
    """Return (primary_binary, sorted_distinct_binaries, had_heredoc).

    Heredoc bodies and quoted strings are removed first, so an embedded Python
    or Node script does not masquerade as a pile of shell commands.
    """
    if not isinstance(cmd, str) or not cmd.strip():
        return None, [], False
    lines = cmd.split("\n")
    kept, i, n_hd = [], 0, 0
    while i < len(lines):
        kept.append(lines[i])
        m = HEREDOC.search(lines[i])
        if m:
            n_hd += 1
            delim = m.group(2)
            i += 1
            while i < len(lines) and lines[i].strip() != delim:
                i += 1
        i += 1
    text = "\n".join(kept)
    text = re.sub(r"'[^']*'", "''", text, flags=re.S)
    text = re.sub(r'"[^"]*"', '""', text, flags=re.S)
    bins = []
    for seg in SPLIT.split(text):
        m = TOKEN.match(seg)
        if not m:
            continue
        if seg[m.end(1):m.end(1) + 1] == "=":      # bare VAR=value, not a command
            continue
        w = m.group(1).split("/")[-1]
        if w.startswith("-") or w in SHELL_KW or w.isdigit() or len(w) > 30:
            continue
        bins.append(w)
    return (bins[0] if bins else None), sorted(set(bins)), n_hd > 0


# ------------------------------------------------------------- transcripts ---

def classify_error(text):
    if not text:
        return "unknown"
    for kind, rx in ERROR_RX:
        if rx.search(text):
            return kind
    return "unclassified"


def ts_ms(s):
    if not s:
        return None
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return None


def result_text(content, limit=200_000):
    """Flatten a tool_result content field to plain text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content[:limit]
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    out.append(b.get("text") or "")
                elif b.get("type") == "image":
                    out.append("<image>")
                else:
                    out.append(json.dumps(b)[:2000])
            else:
                out.append(str(b))
        return "\n".join(out)[:limit]
    return json.dumps(content)[:limit]


def mcp_parts(name):
    if not name or not name.startswith("mcp__"):
        return None, None
    p = name.split("__")
    return (p[1] if len(p) > 1 else None), ("__".join(p[2:]) if len(p) > 2 else None)


def category_of(name):
    if not name:
        return "unknown"
    if name.startswith("mcp__"):
        return "mcp"
    return CATEGORY.get(name, "other")


def parse_transcript(args):
    """Worker: parse one transcript into (calls, urls, turns). Never raises."""
    path, root = args
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        rel = path
    parts = rel.split(os.sep)
    project = parts[0] if len(parts) > 1 else "(root)"
    from_subagent = "subagents" in parts
    calls, urls, pending = [], [], {}
    # One API call is written as several transcript lines - one per content
    # block - all sharing a requestId and repeating the same usage totals. So
    # group by requestId rather than treating each line as an inference.
    turns, order = {}, []
    human_ts = machine_ts = None
    try:
        fh = open(path, errors="replace")
    except OSError:
        return [], [], []
    with fh:
        for line in fh:
            line = line.strip()
            if not line or line[0] != "{":
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            msg = d.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            stamp = d.get("timestamp")
            now = ts_ms(stamp)
            kinds = {b.get("type") for b in content if isinstance(b, dict)}

            if d.get("type") == "assistant":
                rid = d.get("requestId")
                if rid and now:
                    t = turns.get(rid)
                    if t is None:
                        u = msg.get("usage") or {}
                        trig, kind = _trigger(human_ts, machine_ts)
                        t = turns[rid] = {
                            "request_id": rid, "session_id": d.get("sessionId"),
                            "project": project, "transcript": rel,
                            "model": msg.get("model"), "ts": stamp,
                            "trigger_ms": trig, "trigger_kind": kind,
                            "first_ms": now, "last_ms": now,
                            "stop_reason": msg.get("stop_reason"),
                            "input_tokens": u.get("input_tokens") or 0,
                            "output_tokens": u.get("output_tokens") or 0,
                            "cache_read_tokens": u.get("cache_read_input_tokens") or 0,
                            "cache_creation_tokens": u.get("cache_creation_input_tokens") or 0,
                            "service_tier": u.get("service_tier"),
                            "speed": u.get("speed"),
                            "is_sidechain": bool(d.get("isSidechain")) or from_subagent,
                            "entrypoint": d.get("entrypoint"),
                            "blocks": 0, "tool_uses": 0, "thinking": False,
                        }
                        order.append(rid)
                    t["last_ms"] = max(t["last_ms"], now)
                    t["blocks"] += len(content)
                    t["tool_uses"] += sum(1 for b in content
                                          if isinstance(b, dict) and b.get("type") == "tool_use")
                    if "thinking" in kinds:
                        t["thinking"] = True
                    if msg.get("stop_reason"):
                        t["stop_reason"] = msg.get("stop_reason")
            elif now:
                # Anything not from the assistant re-arms the trigger clock. A
                # tool_result or attachment is machine time; a typed prompt is not.
                if "tool_result" in kinds or d.get("type") == "attachment":
                    machine_ts = now
                else:
                    human_ts = now
            for b in content:
                if not isinstance(b, dict):
                    continue
                btype = b.get("type")

                if btype == "tool_use":
                    name = b.get("name")
                    inp = b.get("input")
                    if not isinstance(inp, dict):
                        inp = {"_": inp}
                    server, mtool = mcp_parts(name)
                    cmd = inp.get("command") if name in ("Bash", "BashOutput") else None
                    primary, bins, heredoc = parse_bash(cmd)
                    fp = inp.get("file_path") or inp.get("path") or inp.get("notebook_path")
                    fp = fp if isinstance(fp, str) else None
                    q = inp.get("query") or inp.get("pattern") or inp.get("prompt")
                    caller = b.get("caller")
                    calls.append({
                        "tool_use_id": b.get("id"),
                        "session_id": d.get("sessionId"),
                        "project": project,
                        "transcript": rel,
                        "cwd": d.get("cwd"),
                        "git_branch": d.get("gitBranch"),
                        "entrypoint": d.get("entrypoint"),
                        "cc_version": d.get("version"),
                        "model": msg.get("model"),
                        "ts": stamp,
                        "ts_ms": ts_ms(stamp),
                        "tool_name": name,
                        "tool_category": category_of(name),
                        "mcp_server": server,
                        "mcp_tool": mtool,
                        "is_sidechain": bool(d.get("isSidechain")) or from_subagent,
                        "from_subagent_file": from_subagent,
                        "caller": caller.get("type") if isinstance(caller, dict) else None,
                        "input_bytes": len(json.dumps(inp, ensure_ascii=False, default=str)),
                        "bash_command": cmd[:4000] if isinstance(cmd, str) else None,
                        "bash_primary": primary,
                        "bash_bins": bins,
                        "bash_heredoc": heredoc,
                        "file_path": fp,
                        "file_ext": (os.path.splitext(fp)[1].lower() if fp else None),
                        "url": inp.get("url") if isinstance(inp.get("url"), str) else None,
                        "query": q if isinstance(q, str) else None,
                        "subagent_type": inp.get("subagent_type")
                                         if isinstance(inp.get("subagent_type"), str) else None,
                        "skill_name": inp.get("skill") if isinstance(inp.get("skill"), str) else None,
                        "is_error": None, "error_kind": None, "error_group": None,
                        "error_text": None, "output_bytes": None,
                        "duration_ms": None, "result_ts": None,
                    })
                    pending[b.get("id")] = len(calls) - 1
                    if name == "WebFetch" and isinstance(inp.get("url"), str):
                        urls.append({
                            "source": "WebFetch", "url": inp["url"], "title": None,
                            "query": inp.get("prompt") if isinstance(inp.get("prompt"), str) else None,
                            "project": project, "session_id": d.get("sessionId"),
                            "ts": stamp, "tool_use_id": b.get("id"),
                        })

                elif btype == "tool_result":
                    idx = pending.get(b.get("tool_use_id"))
                    if idx is None:
                        continue
                    body = result_text(b.get("content"))
                    err = bool(b.get("is_error"))
                    row = calls[idx]
                    row["is_error"] = err
                    row["output_bytes"] = len(body)
                    row["result_ts"] = stamp
                    if err:
                        kind = classify_error(body)
                        row["error_kind"] = kind
                        row["error_group"] = ERROR_GROUP.get(kind, "other")
                        row["error_text"] = body[:600]
                    a, z = row["ts_ms"], ts_ms(stamp)
                    if a and z and z >= a:
                        row["duration_ms"] = z - a
                    tur = d.get("toolUseResult")
                    if isinstance(tur, dict) and "results" in tur and "query" in tur:
                        for res in tur.get("results") or []:
                            items = res.get("content") if isinstance(res, dict) else None
                            for it in items or []:
                                if isinstance(it, dict) and it.get("url"):
                                    urls.append({
                                        "source": "WebSearch", "url": it["url"],
                                        "title": it.get("title"), "query": tur.get("query"),
                                        "project": project, "session_id": d.get("sessionId"),
                                        "ts": stamp, "tool_use_id": b.get("tool_use_id"),
                                    })
    for rid in order:
        t = turns[rid]
        if t["trigger_ms"] and t["last_ms"] >= t["trigger_ms"]:
            t["latency_ms"] = t["last_ms"] - t["trigger_ms"]
            t["ttfb_ms"] = t["first_ms"] - t["trigger_ms"]
        else:
            t["latency_ms"] = t["ttfb_ms"] = None
        t["decode_ms"] = t["last_ms"] - t["first_ms"]
        lat = t["latency_ms"]
        t["idle"] = bool(lat and lat > IDLE_CUTOFF_MS)
        t["output_tps"] = (round(t["output_tokens"] / (lat / 1000.0), 2)
                           if lat and not t["idle"] else None)
        cached, fresh = t["cache_read_tokens"], t["cache_creation_tokens"] + t["input_tokens"]
        t["cache_hit_ratio"] = round(cached / (cached + fresh), 4) if (cached + fresh) else None
        for k in ("trigger_ms", "first_ms", "last_ms"):
            t.pop(k)
    return calls, urls, [turns[r] for r in order]


def _trigger(human_ts, machine_ts):
    """Which event started this inference, and when."""
    if human_ts and machine_ts:
        return (machine_ts, "tool_result") if machine_ts >= human_ts else (human_ts, "user")
    if machine_ts:
        return machine_ts, "tool_result"
    if human_ts:
        return human_ts, "user"
    return None, None


# --------------------------------------------------------------- discovery ---

def data_dirs(explicit=None):
    """Candidate Claude Code data directories, most specific first."""
    if explicit:
        return [os.path.abspath(os.path.expanduser(explicit))]
    out = []
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    if env:
        out += [os.path.expanduser(p.strip()) for p in env.split(",") if p.strip()]
    out.append(os.path.expanduser("~/.claude"))
    out.append(os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "claude"))
    seen, uniq = set(), []
    for p in out:
        p = os.path.abspath(p)
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def find_transcripts(explicit=None):
    """Return (project_root, [transcript paths])."""
    for base in data_dirs(explicit):
        root = base if os.path.basename(base) == "projects" else os.path.join(base, "projects")
        if os.path.isdir(root):
            files = glob.glob(os.path.join(root, "**", "*.jsonl"), recursive=True)
            if files:
                return root, sorted(files)
    return None, []


WORKTREE = re.compile(r"-{1,2}claude-worktrees-")


def shorten_projects(keys):
    """Turn encoded cwd directory names into short readable labels.

    Claude Code names each project dir after its cwd with separators replaced by
    '-', so every name carries the same machine-specific preamble
    (``-madsys-juncheng-workspace-foo``). A plain common-prefix strip fails as
    soon as two roots are in play (``/home/x`` and ``/scratch/x``), so instead
    treat any segment shared by at least half the projects as boilerplate and
    drop the leading run of it, tolerating one odd segment in between.

    The worktree marker is split off first: it is the only place a '--' is
    meaningful, and filtering empty segments would otherwise erase it.
    """
    if not keys:
        return {}
    base, tail = {}, {}
    for k in keys:
        parts = WORKTREE.split(k, 1)
        base[k] = parts[0]
        tail[k] = parts[1] if len(parts) > 1 else None

    segs = {k: [s for s in b.lstrip("-").split("-") if s] or [k] for k, b in base.items()}
    uniq = {tuple(v) for v in segs.values()}
    n = len(uniq)
    freq = Counter()
    for parts in uniq:
        freq.update(set(parts))
    boiler = {s for s, c in freq.items() if c >= max(2, (n + 1) // 2)} if n > 1 else set()
    if n == 1:                       # nothing to compare against: drop a home prefix
        only = next(iter(uniq))
        if len(only) > 2 and only[0].lower() in ("home", "users", "user", "root", "mnt", "scratch"):
            boiler = {only[0], only[1]}

    labels = {}
    for key, parts in segs.items():
        last_boiler = -1
        for idx, s in enumerate(parts[:-1]):        # never consume the final segment
            if s in boiler:
                last_boiler = idx
            elif idx - last_boiler > 1:             # two non-boilerplate in a row: name starts
                break
        name = "-".join(parts[last_boiler + 1:]) or "-".join(parts)
        labels[key] = (name + " \u2442 " + tail[key]) if tail[key] else (name or key)
    return labels


def redact_rows(calls, urls, turns=()):
    """Strip everything that could identify a person, machine or codebase."""
    salt = os.urandom(8).hex()

    def h(v, n=7):
        if not v:
            return v
        return hashlib.sha256((salt + str(v)).encode()).hexdigest()[:n]

    projmap = {}
    for r in calls:
        p = r.get("project")
        if p not in projmap:
            projmap[p] = "project-%s" % h(p, 5)
        r["project"] = projmap[p]
        r["transcript"] = h(r.get("transcript"))
        r["cwd"] = None
        r["git_branch"] = h(r.get("git_branch")) if r.get("git_branch") else None
        r["session_id"] = h(r.get("session_id"), 10)
        r["bash_command"] = None
        r["file_path"] = None          # file_ext is kept: it carries no identity
        r["url"] = None
        r["query"] = None
        r["error_text"] = None
    for u in urls:
        u["project"] = projmap.get(u.get("project"), "project-?")
        u["session_id"] = h(u.get("session_id"), 10)
        u["url"] = ""                  # domain is recomputed as "(redacted)"
        u["title"] = None
        u["query"] = None
    for t in turns:
        t["project"] = projmap.get(t.get("project"), "project-?")
        t["session_id"] = h(t.get("session_id"), 10)
        t["transcript"] = h(t.get("transcript"))
        t["request_id"] = h(t.get("request_id"), 10)
    return calls, urls, turns


# Log-spaced edges for the latency histogram the dashboard filters on. Exact
# percentiles go in report.txt; the dashboard interpolates within these buckets.
# ~1.6x steps: fine enough that interpolating inside a bucket stays close to the
# exact percentile, cheap enough that the cube stays small.
LAT_EDGES = [0, 5, 10, 15, 25, 40, 60, 100, 150, 250, 400, 600, 1000, 1500, 2500,
             4000, 6000, 10000, 15000, 25000, 40000, 60000, 100000, 150000, 250000,
             400000, 600000, 1000000, 1800000]

# A machine-triggered turn cannot legitimately take ten minutes: gaps that long
# mean the session was paused, interrupted or resumed, and the wall clock kept
# running. Such turns are flagged and kept out of latency statistics.
IDLE_CUTOFF_MS = 600_000


def lat_bucket(ms):
    lo, hi = 0, len(LAT_EDGES)
    while lo < hi:
        mid = (lo + hi) // 2
        if LAT_EDGES[mid] <= ms:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1 if lo else 0


def pctl(sorted_vals, q):
    """Nearest-rank percentile on an already-sorted list."""
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def ms(v):
    if v is None:
        return "—"
    v = float(v)
    if v < 1000:
        return "%d ms" % round(v)
    if v < 60_000:
        return "%.1f s" % (v / 1000)
    if v < 3_600_000:
        return "%.1f min" % (v / 60_000)
    return "%.1f h" % (v / 3_600_000)


def domain_of(url):
    m = re.match(r"[a-zA-Z][\w+.-]*://([^/?#]*)", url or "")
    host = (m.group(1) if m else "").lower()
    host = host.split("@")[-1].split(":")[0]
    return host[4:] if host.startswith("www.") else host


# ------------------------------------------------------------------ output ---

CSV_SKIP = ("error_text", "bash_command")


def write_table(rows, path_noext, columns, want_parquet=True):
    """Parquet when pyarrow is importable, else gzipped CSV. Returns the path."""
    if want_parquet:
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            pass
        else:
            table = pa.Table.from_pylist([{c: r.get(c) for c in columns} for r in rows])
            path = path_noext + ".parquet"
            pq.write_table(table, path, compression="zstd")
            return path
    path = path_noext + ".csv.gz"
    with gzip.open(path, "wt", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            row = dict(r)
            for k in CSV_SKIP:
                if k in row and row[k]:
                    row[k] = str(row[k]).replace("\n", " ")[:300]
            if isinstance(row.get("bash_bins"), list):
                row["bash_bins"] = " ".join(row["bash_bins"])
            w.writerow({c: row.get(c) for c in columns})
    return path


# ------------------------------------------------------------------- cube ----

STACK = ["shell", "file_read", "file_write", "output", "web", "agent", "user_io", "other"]
GIT_SUB = re.compile(r"\bgit\s+(?:-C\s+\S+\s+)?([a-z][\w-]*)")


def local_parts(iso):
    """(YYYY-MM-DD, hour) in the machine's local timezone."""
    if not iso:
        return None, None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
    except Exception:
        return None, None
    return dt.strftime("%Y-%m-%d"), dt.hour


def topn(counter, n, other="· other"):
    keys = [k for k, _ in counter.most_common(n)]
    return keys + ([other] if len(counter) > len(keys) else [])


def build_cube(calls, urls, turns, git_counter, redacted=False):
    for r in calls:
        r["date"], r["hour"] = local_parts(r["ts"])
    for u in urls:
        u["date"], _ = local_parts(u["ts"])
        u["domain"] = "(redacted)" if redacted else domain_of(u["url"])
    for t in turns:
        t["date"], t["hour"] = local_parts(t["ts"])

    live = [r for r in calls if r["date"]]
    dates = sorted({r["date"] for r in live})
    di = {v: i for i, v in enumerate(dates)}

    proj_n = Counter(r["project"] for r in live)
    projects = [p for p, _ in proj_n.most_common()]
    pi = {v: i for i, v in enumerate(projects)}
    labels = shorten_projects(projects)

    tool_n = Counter(r["tool_name"] for r in live)
    tools = [t for t, _ in tool_n.most_common()]
    ti = {v: i for i, v in enumerate(tools)}
    tcat = {}
    for r in live:
        tcat.setdefault(r["tool_name"], r["tool_category"])

    kind_n = Counter(r["error_kind"] for r in live if r["error_kind"])
    kinds = [k for k, _ in kind_n.most_common()]
    ki = {v: i for i, v in enumerate(kinds)}

    bin_calls = Counter()
    for r in live:
        if r["tool_name"] == "Bash":
            for b in r["bash_bins"] or []:
                bin_calls[b] += 1
    bins = topn(bin_calls, 36)
    bi = {v: i for i, v in enumerate(bins)}

    dom_n = Counter(u["domain"] for u in urls if u.get("date") in di)
    domains = topn(dom_n, 48)
    dmi = {v: i for i, v in enumerate(domains)}

    ext_n = Counter((r["file_ext"] or "(none)") for r in live
                    if r["tool_category"] in ("file_read", "file_write"))
    exts = topn(ext_n, 14)
    xi = {v: i for i, v in enumerate(exts)}

    A, B, Cc, D, E, F, G, J = (defaultdict(lambda: [0] * 6), Counter(), Counter(),
                               defaultdict(lambda: [0, 0]), Counter(), Counter(),
                               set(), Counter())
    sessions = {}
    n_bash = n_heredoc = n_cmds = 0
    for r in live:
        d, p, t = di[r["date"]], pi[r["project"]], ti[r["tool_name"]]
        cell = A[(d, p, t)]
        cell[0] += 1
        cell[1] += 1 if r["is_error"] else 0
        cell[2] += r["output_bytes"] or 0
        cell[3] += r["input_bytes"] or 0
        if r["duration_ms"] is not None:
            cell[4] += r["duration_ms"]
            cell[5] += 1
        if r["error_kind"]:
            B[(d, p, ki[r["error_kind"]])] += 1
        if r["hour"] is not None:
            Cc[(d, p, r["hour"])] += 1
        if r["tool_name"] == "Bash":
            n_bash += 1
            n_heredoc += 1 if r["bash_heredoc"] else 0
            for b in r["bash_bins"] or []:
                n_cmds += 1
                cell2 = D[(d, p, bi.get(b, bi.get("· other", 0)))]
                cell2[0] += 1
                cell2[1] += 1 if r["is_error"] else 0
        if r["tool_category"] in ("file_read", "file_write"):
            F[(d, p, xi.get(r["file_ext"] or "(none)", xi.get("· other", 0)),
               0 if r["tool_category"] == "file_read" else 1)] += 1
        sid = r["session_id"] or "?"
        sessions.setdefault(sid, len(sessions))
        G.add((sessions[sid], d, p))
        J[(d, p, 1 if r["is_sidechain"] else 0)] += 1

    for u in urls:
        if u.get("date") in di and u["project"] in pi:
            E[(di[u["date"]], pi[u["project"]],
               dmi.get(u["domain"], dmi.get("· other", 0)),
               0 if u["source"] == "WebSearch" else 1)] += 1

    # Latency: a log-bucketed histogram per (date, project, tool) so the
    # dashboard can recompute percentiles under any filter combination.
    L = Counter()
    for r in live:
        if r["duration_ms"] is not None:
            L[(di[r["date"]], pi[r["project"]], ti[r["tool_name"]],
               lat_bucket(r["duration_ms"]))] += 1

    tlive = [t for t in turns if t.get("date") in di and t["project"] in pi]
    model_n = Counter(t["model"] for t in tlive if t.get("model"))
    models = [m for m, _ in model_n.most_common()]
    mi = {v: i for i, v in enumerate(models)}
    M, N = Counter(), defaultdict(lambda: [0] * 6)
    for t in tlive:
        if t.get("model") not in mi:
            continue
        d, p, m = di[t["date"]], pi[t["project"]], mi[t["model"]]
        if (t.get("latency_ms") is not None and t.get("trigger_kind") == "tool_result"
                and not t.get("idle")):
            M[(d, p, m, lat_bucket(t["latency_ms"]))] += 1
            N[(d, p, m)][1] += t["latency_ms"]
        cell = N[(d, p, m)]
        cell[0] += 1
        cell[2] += t.get("output_tokens") or 0
        cell[3] += t.get("input_tokens") or 0
        cell[4] += t.get("cache_read_tokens") or 0
        cell[5] += t.get("cache_creation_tokens") or 0

    q_agg = Counter()
    for u in urls:
        if u["source"] == "WebSearch" and u.get("query") and u.get("date") in di:
            q_agg[(str(u["query"])[:160], pi[u["project"]], di[u["date"]])] += 1
    f_agg = Counter()
    for u in urls:
        if u["source"] == "WebFetch" and u.get("url") and u["project"] in pi:
            f_agg[(u["url"], pi[u["project"]])] += 1

    n_all = len(live)
    n_err = sum(1 for r in live if r["is_error"])
    n_notreal = sum(1 for r in live if r["error_group"] in NOT_REAL)
    n_side = sum(1 for r in live if r["is_sidechain"])
    top_cat = Counter(r["tool_category"] for r in live).most_common(1)
    top_tool = tool_n.most_common(1)
    grp_n = Counter(r["error_group"] for r in live if r["error_group"])

    cube = {
        "dates": dates,
        "projects": [{"k": ("" if redacted else p), "n": labels[p]} for p in projects],
        "tools": [{"n": t, "c": tcat.get(t, "other")} for t in tools],
        "errKinds": [{"k": k, "g": ERROR_GROUP.get(k, "other")} for k in kinds],
        "bins": bins, "domains": domains, "exts": exts,
        "A": [[d, p, t] + v for (d, p, t), v in A.items()],
        "B": [[d, p, k, n] for (d, p, k), n in B.items()],
        "C": [[d, p, h, n] for (d, p, h), n in Cc.items()],
        "D": [[d, p, b] + v for (d, p, b), v in D.items()],
        "E": [[d, p, dm, s, n] for (d, p, dm, s), n in E.items()],
        "F": [[d, p, x, rw, n] for (d, p, x, rw), n in F.items()],
        "G": sorted(G),
        "H": [[q, p, d, n] for (q, p, d), n in q_agg.most_common(400)],
        "I": [[u, p, n] for (u, p), n in f_agg.most_common(150)],
        "J": [[d, p, s, n] for (d, p, s), n in J.items()],
        "L": [[d, p, t, b, n] for (d, p, t, b), n in L.items()],
        "M": [[d, p, m, b, n] for (d, p, m, b), n in M.items()],
        "N": [[d, p, m] + v for (d, p, m), v in N.items()],
        "models": models,
        "latEdges": LAT_EDGES,
        "git": git_counter.most_common(12),
    }
    calendar_days = 0
    if dates:
        a = datetime.strptime(dates[0], "%Y-%m-%d")
        b = datetime.strptime(dates[-1], "%Y-%m-%d")
        calendar_days = (b - a).days + 1
    cube["meta"] = {
        "totalCalls": n_all,
        "totalSessions": len(sessions),
        "transcripts": len({r["transcript"] for r in live}),
        "projects": len(projects),
        "bytesIn": sum(r["input_bytes"] or 0 for r in live),
        "bytesOut": sum(r["output_bytes"] or 0 for r in live),
        "bashCalls": n_bash,
        "heredocCalls": n_heredoc,
        "cmdsPerBash": round(n_cmds / n_bash, 1) if n_bash else 0,
        "distinctBins": len(bin_calls),
        "gitInvocations": sum(git_counter.values()),
        "uniqUrls": len({u["url"] for u in urls if u.get("url")}),
        "uniqDomains": len({u["domain"] for u in urls}),
        "turns": len(tlive),
        "timedTurns": sum(1 for t in tlive
                          if t.get("latency_ms") is not None
                          and t.get("trigger_kind") == "tool_result"
                          and not t.get("idle")),
        "idleTurns": sum(1 for t in tlive if t.get("idle")),
        "idleCutoffMs": IDLE_CUTOFF_MS,
        "timedCalls": sum(1 for r in live if r["duration_ms"] is not None),
        "activeDays": len(dates),
        "calendarDays": calendar_days,
        "firstDate": dates[0] if dates else "",
        "lastDate": dates[-1] if dates else "",
        "redacted": redacted,
        "version": __version__,
        "generated": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
    }
    cube["copy"] = build_copy(cube["meta"], n_err, n_notreal, n_side, n_all,
                              top_cat, top_tool, grp_n, len(urls))
    return cube


def build_copy(meta, n_err, n_notreal, n_side, n_all, top_cat, top_tool, grp_n, n_urls):
    """Headline and panel copy, written from this corpus rather than a template."""
    pc = lambda a, b: (100.0 * a / b) if b else 0.0
    real = n_err - n_notreal
    tool_name, tool_n = (top_tool[0] if top_tool else ("—", 0))
    bits = []
    if n_err and pc(n_notreal, n_err) >= 35:
        bits.append("most logged “failures” are your own guardrails and hooks firing, "
                    "not tools breaking")
    elif n_err and grp_n.get("command_failed", 0) >= 0.4 * n_err:
        bits.append("the failures that matter are commands exiting non-zero, not the harness")
    elif n_err and grp_n.get("agent_mistake", 0) >= 0.35 * n_err:
        bits.append("most failures are the model mis-addressing a file or schema, "
                    "not the tool refusing")
    elif n_err == 0:
        bits.append("not one call in this corpus returned an error")
    else:
        bits.append("failures are spread thin across every tool")
    if pc(n_side, n_all) >= 40:
        bits.append("and %.0f%% of all calls come from subagents rather than the main thread"
                    % pc(n_side, n_all))
    elif tool_n:
        bits.append("and %s alone accounts for %.0f%% of every call"
                    % (tool_name, pc(tool_n, n_all)))
    idle = meta["calendarDays"] - meta["activeDays"]
    return {
        "thesis": ("Every tool call recorded across your local sessions, parsed from the raw "
                   "JSONL transcripts. The headline: " + ", ".join(bits) + "."),
        "timeline": ("Active days only — %d of the %d calendar days in this window had no "
                     "sessions. Drag across the chart to set the date range; the error strip "
                     "underneath shares the same x axis rather than borrowing a second y scale."
                     % (idle, meta["calendarDays"])),
        "bash": ("Commands actually invoked, with heredoc bodies and quoted strings stripped so "
                 "embedded scripts don’t masquerade as shell. A single Bash call runs %s commands "
                 "on average, so shares sum past 100%%." % meta["cmdsPerBash"]),
        "tools": ("Bar length is call count on a linear scale — %s alone is %.0f%% of every call, "
                  "so the tail is read from its labels. The red tip is the portion that returned "
                  "an error." % (tool_name, pc(tool_n, n_all))),
        "source": ("%s transcripts parsed from %s. %s tool calls, %s sessions, %s projects."
                   % (fmt_int(meta["transcripts"]), "your Claude Code data directory",
                      fmt_int(meta["totalCalls"]), fmt_int(meta["totalSessions"]),
                      meta["projects"])),
        "latTool": ("Wall clock from the tool call being issued to its result landing. It "
                    "includes the work itself and, where a call needed approval, however long "
                    "that took — which is why percentiles are shown rather than a mean. "
                    "Buckets are log-spaced; percentiles interpolate within them."),
        "latTurn": ("Wall clock from the tool result that triggered an inference to the last "
                    "block of the model's reply — queue, prefill and decode together. Turns you "
                    "started by typing are excluded, and so are %s turns whose trigger sat more "
                    "than %s in the past because the session was paused or resumed."
                    % (fmt_int(meta.get("idleTurns", 0)), _ms_short(meta.get("idleCutoffMs", 0)))),
        "genuine": ("%s of %s errors (%.0f%%) were the operator’s guardrails or hook transport, "
                    "not a tool defect; the genuine failure rate is %.2f%% of all calls."
                    % (fmt_int(n_notreal), fmt_int(n_err), pc(n_notreal, n_err), pc(real, n_all))
                    if n_err else "No errors recorded in this corpus."),
    }


def fmt_int(n):
    return "{:,}".format(int(n))


def _ms_short(v):
    return ms(v) if v else "—"


# ---------------------------------------------------------------- dashboard ---

HTML_TEMPLATE = r"""<title>Tool Call Ledger</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">
<style>
:root{
  --plane:#f9f9f7; --surface:#fcfcfb; --sunken:#f2f1ec;
  --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --rule:rgba(11,11,11,.10); --rule-2:rgba(11,11,11,.05);
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100;
  --s5:#e87ba4; --s6:#008300; --s7:#4a3aa7; --s8:#e34948;
  --good:#0ca30c; --warn:#fab219; --serious:#ec835a; --critical:#d03b3b;
  --sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --plane:#0d0d0d; --surface:#1a1a19; --sunken:#131312;
  --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --rule:rgba(255,255,255,.11); --rule-2:rgba(255,255,255,.05);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500;
  --s5:#d55181; --s6:#008300; --s7:#9085e9; --s8:#e66767;
  color-scheme:dark;
}}
:root[data-theme="dark"]{
  --plane:#0d0d0d; --surface:#1a1a19; --sunken:#131312;
  --ink:#ffffff; --ink-2:#c3c2b7; --muted:#898781;
  --grid:#2c2c2a; --axis:#383835; --rule:rgba(255,255,255,.11); --rule-2:rgba(255,255,255,.05);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500;
  --s5:#d55181; --s6:#008300; --s7:#9085e9; --s8:#e66767;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{background:var(--plane);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:34px 22px 80px}
h1,h2,h3{margin:0;text-wrap:balance}
.eyebrow{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:.13em;
  text-transform:uppercase;color:var(--muted)}
a{color:var(--s1)}
:focus-visible{outline:2px solid var(--s1);outline-offset:2px;border-radius:3px}

/* ---------- masthead ---------- */
.mast{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-end;justify-content:space-between;
  padding-bottom:20px;border-bottom:2px solid var(--ink)}
.mast h1{font-size:clamp(28px,4.4vw,42px);font-weight:600;letter-spacing:-.022em;line-height:1.04}
.mast p{margin:9px 0 0;color:var(--ink-2);max-width:60ch;font-size:15px}
.window{font-family:var(--mono);font-size:12px;color:var(--muted);text-align:right;
  line-height:1.75;white-space:nowrap}
.window b{color:var(--ink);font-weight:500}

/* ---------- filter rail ---------- */
.rail{position:sticky;top:0;z-index:30;background:var(--plane);
  border-bottom:1px solid var(--rule);margin-bottom:26px;padding:14px 0 13px}
.rail-row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.rail-lbl{font-family:var(--mono);font-size:10px;letter-spacing:.13em;text-transform:uppercase;
  color:var(--muted);flex:0 0 auto}
.chips{display:flex;gap:5px;flex-wrap:wrap;flex:1 1 380px;min-width:0}
.chip{font-family:var(--mono);font-size:11.5px;padding:3.5px 9px;border-radius:11px;cursor:pointer;
  max-width:min(340px,42vw);overflow:hidden;text-overflow:ellipsis;
  border:1px solid var(--rule);background:transparent;color:var(--ink-2);white-space:nowrap;
  transition:background .12s,border-color .12s,color .12s;font-weight:400}
.chip:hover{border-color:var(--axis);color:var(--ink)}
.chip[aria-pressed="true"]{background:var(--s1);border-color:var(--s1);color:#fff;font-weight:500}
.chip .cn{opacity:.62;margin-left:5px}
.btn{font-family:var(--mono);font-size:11.5px;padding:3.5px 10px;border-radius:5px;cursor:pointer;
  border:1px solid var(--rule);background:transparent;color:var(--ink-2)}
.btn:hover{border-color:var(--axis);color:var(--ink)}
.btn[aria-pressed="true"]{background:var(--ink);border-color:var(--ink);color:var(--plane)}
.scope{font-family:var(--mono);font-size:11.5px;color:var(--muted);margin-left:auto;white-space:nowrap}
.scope b{color:var(--ink);font-weight:500}

/* ---------- kpi strip ---------- */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));gap:1px;
  background:var(--rule);border:1px solid var(--rule);margin-bottom:30px}
.kpi{background:var(--surface);padding:15px 17px 16px}
.kpi .k{font-family:var(--mono);font-size:10px;letter-spacing:.11em;text-transform:uppercase;
  color:var(--muted);display:block;margin-bottom:7px}
.kpi .v{font-family:var(--mono);font-size:29px;font-weight:600;letter-spacing:-.028em;
  line-height:1;display:block;color:var(--ink)}
.kpi .v small{font-size:16px;font-weight:500;letter-spacing:-.01em}
.kpi .sub{font-size:12px;color:var(--ink-2);margin-top:7px;display:block;line-height:1.4}
.kpi .sub em{font-style:normal;font-family:var(--mono);color:var(--muted)}

/* ---------- panels ---------- */
.panel{background:var(--surface);border:1px solid var(--rule);padding:20px 21px 22px;margin-bottom:20px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
.grid2>.panel{margin-bottom:0;min-width:0}
@media (max-width:860px){.grid2{grid-template-columns:1fr}}
.phead{display:flex;justify-content:space-between;align-items:baseline;gap:14px;margin-bottom:3px}
.panel h2{font-size:16.5px;font-weight:600;letter-spacing:-.012em}
.pnote{font-size:12.5px;color:var(--ink-2);margin:5px 0 16px;max-width:74ch;line-height:1.45}
.pmeta{font-family:var(--mono);font-size:11px;color:var(--muted);white-space:nowrap}

/* ---------- html bar lists ---------- */
.bars{display:flex;flex-direction:column;gap:7px}
.bar{display:grid;grid-template-columns:var(--lw,104px) 1fr auto;gap:11px;align-items:center}
.bar .bl{font-family:var(--mono);font-size:12px;color:var(--ink-2);text-align:right;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .bt{position:relative;height:15px;background:var(--sunken);border-radius:2px;overflow:hidden}
.bar .bf{position:absolute;inset:0 auto 0 0;border-radius:2px 4px 4px 2px;min-width:2px}
.bar .bf.split{border-radius:2px 0 0 2px}
.bar .bf2{position:absolute;top:0;bottom:0;border-radius:0 4px 4px 0}
.bar .bv{font-family:var(--mono);font-size:12px;font-variant-numeric:tabular-nums;
  color:var(--ink);min-width:var(--vw,58px);text-align:right}
.bar .bv i{font-style:normal;color:var(--muted);font-size:11px}
.bar:hover .bl{color:var(--ink)}

/* ---------- composition bar ---------- */
.comp{display:flex;height:34px;gap:2px;margin:6px 0 14px}
.comp span{position:relative;display:flex;align-items:center;justify-content:center;
  font-family:var(--mono);font-size:11px;font-weight:500;color:#fff;overflow:hidden;
  border-radius:2px;min-width:2px}
.legend{display:flex;flex-wrap:wrap;gap:5px 18px;margin-top:2px}
.lgi{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--ink-2)}
.lgi .sw{width:11px;height:11px;border-radius:2px;flex:0 0 auto}
.lgi b{font-family:var(--mono);font-weight:500;color:var(--ink);font-variant-numeric:tabular-nums}

.lat-switch{display:flex;gap:5px;margin:0 0 16px}
.latgrid{display:grid;grid-template-columns:1fr 214px;gap:22px;align-items:start}
@media (max-width:760px){.latgrid{grid-template-columns:1fr}}
.latstats{display:flex;flex-direction:column;gap:1px;background:var(--rule);
  border:1px solid var(--rule)}
.latstat{background:var(--surface);padding:9px 12px;display:flex;justify-content:space-between;
  align-items:baseline;gap:10px}
.latstat .k{font-family:var(--mono);font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--muted)}
.latstat .v{font-family:var(--mono);font-size:15px;font-weight:600;color:var(--ink);
  font-variant-numeric:tabular-nums}
.latstat.hi .v{color:var(--critical)}

/* ---------- svg timeline ---------- */
.tlwrap{position:relative;user-select:none;touch-action:pan-y}
svg{display:block;width:100%;height:auto;overflow:visible}
.tl-band{fill:transparent;cursor:col-resize}
.tl-band:hover{fill:var(--rule-2)}
.ax{font-family:var(--mono);font-size:9.5px;fill:var(--muted)}
.gl{stroke:var(--grid);stroke-width:1}
.bl-axis{stroke:var(--axis);stroke-width:1}
.dl{font-family:var(--mono);font-size:10px;font-weight:500;fill:var(--ink)}
.brush{fill:var(--s1);opacity:.10}
.brush-edge{stroke:var(--s1);stroke-width:1.5}

/* ---------- tooltip ---------- */
.tip{position:fixed;z-index:60;pointer-events:none;background:var(--ink);color:var(--plane);
  font-family:var(--mono);font-size:11.5px;line-height:1.55;padding:8px 10px;border-radius:5px;
  max-width:290px;box-shadow:0 4px 16px rgba(0,0,0,.24)}
.tip b{font-weight:600}
.tip .r{display:flex;justify-content:space-between;gap:14px}
.tip .r i{font-style:normal;opacity:.72}

/* ---------- tables ---------- */
.tabs{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap;border-bottom:1px solid var(--rule)}
.tab{font-family:var(--mono);font-size:12px;padding:7px 12px;cursor:pointer;background:none;
  border:none;border-bottom:2px solid transparent;color:var(--muted);margin-bottom:-1px}
.tab:hover{color:var(--ink)}
.tab[aria-selected="true"]{color:var(--ink);border-bottom-color:var(--s1);font-weight:500}
.tscroll{overflow-x:auto;max-height:430px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;
  color:var(--muted);text-align:left;font-weight:500;padding:0 12px 8px 0;position:sticky;top:0;
  background:var(--surface);border-bottom:1px solid var(--rule)}
td{padding:6px 12px 6px 0;border-bottom:1px solid var(--rule-2);vertical-align:top}
td.n{font-family:var(--mono);font-variant-numeric:tabular-nums;text-align:right;white-space:nowrap}
td.m{font-family:var(--mono);font-size:12px}
tr:hover td{background:var(--rule-2)}
.pill{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10.5px;
  padding:1.5px 7px;border-radius:9px;white-space:nowrap;border:1px solid transparent}
.pill .dot{width:6px;height:6px;border-radius:50%;flex:0 0 auto}
.qtxt{max-width:1px}

/* ---------- footer ---------- */
.foot{margin-top:34px;padding-top:18px;border-top:1px solid var(--rule);
  font-size:12.5px;color:var(--ink-2);line-height:1.6}
.foot code{font-family:var(--mono);font-size:11.5px;background:var(--sunken);
  padding:1px 5px;border-radius:3px;color:var(--ink)}
.foot ul{margin:8px 0 0;padding-left:19px}
.foot li{margin:4px 0}
.empty{padding:34px 0;text-align:center;color:var(--muted);font-family:var(--mono);font-size:12.5px}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>

<div class="wrap">
  <header class="mast">
    <div>
      <div class="eyebrow">Claude Code · session transcript audit</div>
      <h1>Tool Call Ledger</h1>
      <p id="thesis"></p>
    </div>
    <div class="window" id="window"></div>
  </header>

  <div class="rail">
    <div class="rail-row" style="margin-bottom:9px">
      <span class="rail-lbl">Project</span>
      <div class="chips" id="chips"></div>
    </div>
    <div class="rail-row">
      <span class="rail-lbl">Range</span>
      <span id="ranges"></span>
      <button class="btn" id="reset">Reset all</button>
      <span class="scope" id="scope"></span>
    </div>
  </div>

  <div class="kpis" id="kpis"></div>

  <section class="panel">
    <div class="phead">
      <h2>Daily volume by tool category</h2>
      <span class="pmeta" id="tl-meta"></span>
    </div>
    <p class="pnote" id="note-timeline"></p>
    <div class="tlwrap" id="tlwrap"></div>
    <div class="legend" id="tl-legend" style="margin-top:12px"></div>
  </section>

  <div class="grid2">
    <section class="panel">
      <div class="phead"><h2>Tools by call count</h2><span class="pmeta" id="tools-meta"></span></div>
      <p class="pnote" id="note-tools"></p>
      <div class="bars" id="tools" style="--lw:112px;--vw:74px"></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>Why calls fail</h2><span class="pmeta" id="fail-meta"></span></div>
      <p class="pnote">Errors split by root cause. The first two bands are the operator’s own
      guardrails and hook transport — real friction, but not a tool defect.</p>
      <div class="comp" id="fail-comp"></div>
      <div class="legend" id="fail-legend"></div>
      <div class="bars" id="fail-kinds" style="--lw:132px;--vw:64px;margin-top:18px"></div>
    </section>
  </div>


  <section class="panel">
    <div class="phead">
      <h2>Latency</h2>
      <span class="pmeta" id="lat-meta"></span>
    </div>
    <p class="pnote" id="note-lat"></p>
    <div class="lat-switch" role="tablist">
      <button class="btn" data-lat="tool" aria-pressed="true">Tool calls</button>
      <button class="btn" data-lat="turn" aria-pressed="false">Model turns</button>
    </div>
    <div class="latgrid">
      <div>
        <div id="lat-hist"></div>
      </div>
      <div class="latstats" id="lat-stats"></div>
    </div>
    <div class="bars" id="lat-bars" style="--lw:118px;--vw:118px;margin-top:20px"></div>
  </section>

  <div class="grid2">
    <section class="panel">
      <div class="phead"><h2>Inside Bash</h2><span class="pmeta" id="bash-meta"></span></div>
      <p class="pnote" id="note-bash"></p>
      <div class="bars" id="bash" style="--lw:78px;--vw:82px"></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>Where the web calls went</h2><span class="pmeta" id="web-meta"></span></div>
      <p class="pnote">Blue is links returned by a search; orange is a page actually fetched. Most
      search results are read from the snippet and never opened.</p>
      <div class="bars" id="web" style="--lw:150px;--vw:66px"></div>
      <div class="legend" id="web-legend" style="margin-top:13px"></div>
    </section>
  </div>

  <div class="grid2">
    <section class="panel">
      <div class="phead"><h2>Hour of day</h2><span class="pmeta">local time</span></div>
      <p class="pnote">Calls by wall-clock hour — a bimodal working rhythm with a hard stop overnight.</p>
      <div id="hours"></div>
    </section>
    <section class="panel">
      <div class="phead"><h2>File types touched</h2><span class="pmeta" id="ext-meta"></span></div>
      <p class="pnote">Read versus written, by extension, across the Read / Edit / Write tools.</p>
      <div class="bars" id="exts" style="--lw:66px;--vw:92px"></div>
      <div class="legend" id="ext-legend" style="margin-top:13px"></div>
    </section>
  </div>

  <section class="panel">
    <div class="phead"><h2>Detail</h2><span class="pmeta" id="tab-meta"></span></div>
    <div class="tabs" role="tablist" id="tabs">
      <button class="tab" role="tab" data-tab="tools" aria-selected="true">Tool table</button>
      <button class="tab" role="tab" data-tab="errors" aria-selected="false">Error kinds</button>
      <button class="tab" role="tab" data-tab="queries" aria-selected="false">Search queries</button>
      <button class="tab" role="tab" data-tab="urls" aria-selected="false">Fetched URLs</button>
      <button class="tab" role="tab" data-tab="git" aria-selected="false" id="tab-git">Git subcommands</button>
    </div>
    <div class="tscroll" id="tblwrap"></div>
  </section>

  <footer class="foot" id="foot"></footer>

</div>

<script id="cube" type="application/json">/*__CUBE__*/</script>
<script>
(function(){
"use strict";
const C = JSON.parse(document.getElementById('cube').textContent);
const nD = C.dates.length, nP = C.projects.length;
const fmt = n => n.toLocaleString('en-US');
const pct = (a,b) => b ? (100*a/b) : 0;
const p1  = v => v.toFixed(1)+'%';
const p2  = v => v.toFixed(2)+'%';
const bytes = b => b >= 1e9 ? (b/1e9).toFixed(1)+' GB' : b >= 1e6 ? (b/1e6).toFixed(0)+' MB' : (b/1e3).toFixed(0)+' KB';
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const mdy = iso => { const [y,m,d] = iso.split('-'); return m+'/'+(+d); };

/* ---- category + group vocab ---- */
const CATS = ['shell','file_read','file_write','output','web','agent','user_io'];
const CATLBL = {shell:'Shell',file_read:'File read',file_write:'File write',output:'Structured output',
  web:'Web',agent:'Agent',user_io:'User I/O',other:'Other'};
const CATCOL = {shell:'--s1',file_read:'--s2',file_write:'--s3',output:'--s4',
  web:'--s5',agent:'--s6',user_io:'--s7',other:'--axis'};
const catOf = c => CATS.includes(c) ? c : 'other';
const STACK = CATS.concat('other');

const GRPS = ['command_failed','blocked_by_policy','hook_infra','agent_mistake','infra_limit','other'];
const GRPLBL = {command_failed:'Command failed',blocked_by_policy:'Blocked by policy',
  hook_infra:'Hook infrastructure',agent_mistake:'Agent mistake',infra_limit:'Platform limit',other:'Other'};
const GRPCOL = {command_failed:'--s1',blocked_by_policy:'--s2',hook_infra:'--s3',
  agent_mistake:'--s4',infra_limit:'--s5',other:'--axis'};
const NOTREAL = new Set(['blocked_by_policy','hook_infra']);
const KINDLBL = {nonzero_exit:'non-zero exit',hook_gate:'Fact-Forcing Gate',hook_timeout:'PreToolUse timeout',
  file_too_large:'file too large',file_not_found:'file not found',policy_blocked:'auto-mode block',
  timeout:'command timeout',schema_invalid:'schema mismatch',stale_read:'stale read',no_match:'no match',
  concurrency_limit:'subagent cap',user_rejected:'user rejected',bad_input:'bad input',
  model_unavailable:'model unavailable',worktree_isolated:'worktree isolated',network:'network',
  fetch_blocked:'fetch blocked',edit_ambiguous:'ambiguous edit',permission_infra:'permission stream',
  script_invalid:'invalid script',noop_edit:'no-op edit',unclassified:'unclassified'};
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

/* ---- state ---- */
let sel = new Set(Array.from({length:nP},(_,i)=>i));
let d0 = 0, d1 = nD-1;
const inF = (d,p) => d>=d0 && d<=d1 && sel.has(p);

/* ---- aggregation ---- */
function agg(){
  const T = C.tools.map(()=>({n:0,e:0,ob:0,ib:0,ds:0,dn:0}));
  const cat = {}; STACK.forEach(c=>cat[c]=0);
  const daily = C.dates.map(()=>({n:0,e:0,by:Object.fromEntries(STACK.map(c=>[c,0]))}));
  let n=0,e=0,ob=0,ib=0,ds=0,dn=0;
  for (const [d,p,t,cn,ce,cob,cib,cds,cdn] of C.A){
    if(!inF(d,p)) continue;
    const T0=T[t]; T0.n+=cn; T0.e+=ce; T0.ob+=cob; T0.ib+=cib; T0.ds+=cds; T0.dn+=cdn;
    const c = catOf(C.tools[t].c);
    cat[c]+=cn; daily[d].n+=cn; daily[d].e+=ce; daily[d].by[c]+=cn;
    n+=cn; e+=ce; ob+=cob; ib+=cib;
    if(C.tools[t].n!=='AskUserQuestion'){ ds+=cds; dn+=cdn; }
  }
  const K = C.errKinds.map(()=>0), G = {}; GRPS.forEach(g=>G[g]=0);
  for (const [d,p,k,cn] of C.B){ if(!inF(d,p)) continue; K[k]+=cn; G[C.errKinds[k].g]+=cn; }
  const H = new Array(24).fill(0);
  for (const [d,p,h,cn] of C.C){ if(inF(d,p)) H[h]+=cn; }
  const B = C.bins.map(()=>({n:0,e:0}));
  for (const [d,p,b,cn,ce] of C.D){ if(!inF(d,p)){continue;} B[b].n+=cn; B[b].e+=ce; }
  const W = C.domains.map(()=>[0,0]);
  for (const [d,p,dm,src,cn] of C.E){ if(inF(d,p)) W[dm][src]+=cn; }
  const X = C.exts.map(()=>[0,0]);
  for (const [d,p,x,rw,cn] of C.F){ if(inF(d,p)) X[x][rw]+=cn; }
  const S = new Set();
  for (const [s,d,p] of C.G){ if(inF(d,p)) S.add(s); }
  let side=0, main=0;
  for (const [d,p,is,cn] of C.J){ if(!inF(d,p)) continue; if(is) side+=cn; else main+=cn; }
  const NB=C.latEdges.length;
  const LT=new Array(NB).fill(0), LM=new Array(NB).fill(0);
  const LTby=C.tools.map(()=>new Array(NB).fill(0));
  const LMby=(C.models||[]).map(()=>new Array(NB).fill(0));
  for (const [d,p,t,b,cn] of (C.L||[])){ if(!inF(d,p)) continue; LT[b]+=cn; LTby[t][b]+=cn; }
  for (const [d,p,m,b,cn] of (C.M||[])){ if(!inF(d,p)) continue; LM[b]+=cn; LMby[m][b]+=cn; }
  let turnN=0, turnLat=0, turnOut=0, turnIn=0, cacheRead=0, cacheCreate=0;
  for (const [d,p,m,n,lat,out,inp,cr,cc] of (C.N||[])){
    if(!inF(d,p)) continue;
    turnN+=n; turnLat+=lat; turnOut+=out; turnIn+=inp; cacheRead+=cr; cacheCreate+=cc;
  }
  let bashCalls=0, bashErr=0;
  C.tools.forEach((t,i)=>{ if(t.n==='Bash'){bashCalls=T[i].n; bashErr=T[i].e;} });
  const notReal = GRPS.filter(g=>NOTREAL.has(g)).reduce((a,g)=>a+G[g],0);
  return {T,cat,daily,n,e,ob,ib,ds,dn,K,G,H,B,W,X,sessions:S.size,side,main,bashCalls,bashErr,
          notReal, LT,LM,LTby,LMby, turnN, turnSecs:turnLat/1000, turnOut,
          cacheRead, cacheFresh:cacheCreate+turnIn};
}

/* ---- tooltip ---- */
const tip = document.createElement('div');
tip.className='tip'; tip.hidden=true; document.body.appendChild(tip);
function showTip(ev,html){
  tip.innerHTML=html; tip.hidden=false;
  const r=tip.getBoundingClientRect();
  let x=ev.clientX+14, y=ev.clientY+14;
  if(x+r.width>innerWidth-8) x=ev.clientX-r.width-14;
  if(y+r.height>innerHeight-8) y=ev.clientY-r.height-14;
  tip.style.left=Math.max(6,x)+'px'; tip.style.top=Math.max(6,y)+'px';
}
const hideTip = () => { tip.hidden=true; };
function bindTip(el,html){
  el.addEventListener('pointerenter',e=>showTip(e,html));
  el.addEventListener('pointermove',e=>showTip(e,html));
  el.addEventListener('pointerleave',hideTip);
}

/* ---- html bar list ---- */
function barList(host, rows, opts){
  const o = opts||{};
  host.innerHTML='';
  if(!rows.length){ host.innerHTML='<div class="empty">No calls in this selection.</div>'; return; }
  const max = Math.max(...rows.map(r=>r.v), 1);
  for(const r of rows){
    const el=document.createElement('div'); el.className='bar';
    const w = Math.max(0.6, 100*r.v/max);
    const seg2 = r.v2 ? 100*r.v2/max : 0;
    el.innerHTML =
      '<span class="bl" title="'+esc(r.label)+'">'+esc(r.label)+'</span>'+
      '<span class="bt"><span class="bf'+(r.v2!=null?' split':'')+'" style="width:'+w+'%;background:'+
        (r.color||'var(--s1)')+'"></span>'+
        (r.v2!=null?'<span class="bf2" style="left:'+w+'%;width:'+seg2+'%;background:'+(r.color2||'var(--s2)')+'"></span>':'')+
      '</span>'+
      '<span class="bv">'+r.right+'</span>';
    if(r.tip) bindTip(el, r.tip);
    host.appendChild(el);
  }
}

/* ---- timeline (SVG) ---- */
const W=1000, HT=196, HE=44, PADL=42, PADR=10, PADT=10, GAPY=26;
function drawTimeline(A){
  const host=document.getElementById('tlwrap');
  const days=C.dates.map((iso,i)=>({i,iso,d:A.daily[i]}));
  const max=Math.max(...days.map(d=>d.d.n),1);
  const emax=Math.max(...days.map(d=>d.d.n?pct(d.d.e,d.d.n):0),1);
  const iw=W-PADL-PADR, bw=iw/nD, bar=Math.max(3,bw*0.72), off=(bw-bar)/2;
  const y = v => PADT+(HT-PADT)*(1-v/max);
  const ye = v => HT+GAPY+HE*(1-v/emax);
  const ticks=[0,.25,.5,.75,1].map(f=>Math.round(max*f));
  let s=`<svg viewBox="0 0 ${W} ${HT+GAPY+HE+26}" role="img" aria-label="Daily tool calls by category with error-rate strip">`;
  for(const t of [...new Set(ticks)]){
    s+=`<line class="gl" x1="${PADL}" x2="${W-PADR}" y1="${y(t)}" y2="${y(t)}"/>`;
    s+=`<text class="ax" x="${PADL-7}" y="${y(t)+3}" text-anchor="end">${t>=1000?(t/1000).toFixed(t>=10000?0:1)+'k':t}</text>`;
  }
  s+=`<text class="ax" x="${PADL-7}" y="${ye(emax)+3}" text-anchor="end">${emax.toFixed(0)}%</text>`;
  s+=`<text class="ax" x="${PADL-7}" y="${ye(0)+3}" text-anchor="end">0</text>`;
  s+=`<line class="bl-axis" x1="${PADL}" x2="${W-PADR}" y1="${ye(0)}" y2="${ye(0)}"/>`;
  s+=`<text class="ax" x="${PADL}" y="${HT+GAPY-9}" style="font-size:9px">ERROR RATE / DAY</text>`;
  if(d0>0||d1<nD-1){
    const bx=PADL+d0*bw, bw2=(d1-d0+1)*bw;
    s+=`<rect class="brush" x="${bx}" y="${PADT-6}" width="${bw2}" height="${HT+GAPY+HE-PADT+6}"/>`;
    s+=`<line class="brush-edge" x1="${bx}" x2="${bx}" y1="${PADT-6}" y2="${ye(0)}"/>`;
    s+=`<line class="brush-edge" x1="${bx+bw2}" x2="${bx+bw2}" y1="${PADT-6}" y2="${ye(0)}"/>`;
  }
  let peak=days[0];
  for(const d of days){
    const x=PADL+d.i*bw+off;
    if(d.d.n>peak.d.n) peak=d;
    let acc=0;
    for(const c of STACK){
      const v=d.d.by[c]; if(!v) continue;
      const h=(HT-PADT)*v/max, yy=y(acc+v);
      s+=`<rect x="${x.toFixed(2)}" y="${yy.toFixed(2)}" width="${bar.toFixed(2)}" height="${Math.max(0.7,h-2).toFixed(2)}" fill="var(${CATCOL[c]})" rx="1.5"/>`;
      acc+=v;
    }
    if(d.d.n){
      const er=pct(d.d.e,d.d.n), h=HE*er/emax;
      s+=`<rect x="${x.toFixed(2)}" y="${(ye(er)).toFixed(2)}" width="${bar.toFixed(2)}" height="${Math.max(0.8,h).toFixed(2)}" fill="var(--critical)" rx="1.5"/>`;
    }
    if(d.i%Math.ceil(nD/13)===0)
      s+=`<text class="ax" x="${(PADL+d.i*bw+bw/2).toFixed(1)}" y="${ye(0)+14}" text-anchor="middle">${mdy(d.iso)}</text>`;
  }
  if(peak.d.n>0){
    const px=PADL+peak.i*bw+bw/2;
    s+=`<text class="dl" x="${px.toFixed(1)}" y="${(y(peak.d.n)-6).toFixed(1)}" text-anchor="${peak.i>nD*0.8?'end':(peak.i<nD*0.2?'start':'middle')}">${fmt(peak.d.n)}</text>`;
  }
  for(const d of days)
    s+=`<rect class="tl-band" data-i="${d.i}" x="${(PADL+d.i*bw).toFixed(2)}" y="${PADT-6}" width="${bw.toFixed(2)}" height="${HT+GAPY+HE-PADT+6}"/>`;
  s+='</svg>';
  host.innerHTML=s;
  const svg=host.querySelector('svg');
  host.querySelectorAll('.tl-band').forEach(b=>{
    const i=+b.dataset.i, d=A.daily[i];
    const rows=STACK.filter(c=>d.by[c]).map(c=>
      `<div class="r"><i>${CATLBL[c]}</i><b>${fmt(d.by[c])}</b></div>`).join('');
    bindTip(b,`<b>${C.dates[i]}</b><div class="r"><i>calls</i><b>${fmt(d.n)}</b></div>`+
      `<div class="r"><i>errors</i><b>${fmt(d.e)} · ${p1(pct(d.e,d.n))}</b></div>`+
      (rows?'<div style="height:5px"></div>'+rows:''));
  });
  /* brush */
  let dragFrom=null;
  const idxAt = ev => {
    const r=svg.getBoundingClientRect();
    const x=(ev.clientX-r.left)/r.width*W;
    return Math.max(0,Math.min(nD-1,Math.floor((x-PADL)/bw)));
  };
  svg.addEventListener('pointerdown',ev=>{
    if(ev.button) return;
    dragFrom=idxAt(ev); svg.setPointerCapture(ev.pointerId); ev.preventDefault();
  });
  svg.addEventListener('pointermove',ev=>{
    if(dragFrom===null) return;
    const j=idxAt(ev); d0=Math.min(dragFrom,j); d1=Math.max(dragFrom,j); render();
  });
  svg.addEventListener('pointerup',ev=>{
    if(dragFrom===null) return;
    const j=idxAt(ev);
    if(j===dragFrom){ d0=0; d1=nD-1; }
    dragFrom=null; render(); hideTip();
  });
}

/* ---- hour chart ---- */
function drawHours(A){
  const max=Math.max(...A.H,1);
  let s=`<svg viewBox="0 0 480 168" role="img" aria-label="Tool calls by hour of day"><g>`;
  const bw=480/24, bar=bw*0.66;
  let peak=0; A.H.forEach((v,i)=>{ if(v>A.H[peak]) peak=i; });
  for(let h=0;h<24;h++){
    const v=A.H[h], hh=136*v/max;
    s+=`<rect x="${(h*bw+(bw-bar)/2).toFixed(2)}" y="${(140-hh).toFixed(2)}" width="${bar.toFixed(2)}" height="${Math.max(v?1:0,hh).toFixed(2)}" fill="var(--s1)" rx="1.5"/>`;
    if(h%3===0) s+=`<text class="ax" x="${(h*bw+bw/2).toFixed(1)}" y="156" text-anchor="middle">${String(h).padStart(2,'0')}</text>`;
  }
  if(A.H[peak]) s+=`<text class="dl" x="${(peak*bw+bw/2).toFixed(1)}" y="${(140-136*A.H[peak]/max-5).toFixed(1)}" text-anchor="${peak>19?'end':'middle'}">${fmt(A.H[peak])}</text>`;
  s+=`<line class="bl-axis" x1="0" x2="480" y1="140.5" y2="140.5"/></g></svg>`;
  const host=document.getElementById('hours'); host.innerHTML=s;
  host.querySelectorAll('rect').forEach((r,i)=>bindTip(r,
    `<b>${String(i).padStart(2,'0')}:00</b><div class="r"><i>calls</i><b>${fmt(A.H[i])}</b></div>`));
}

/* ---- tables ---- */
let tab='tools';
function drawTable(A){
  const w=document.getElementById('tblwrap');
  const meta=document.getElementById('tab-meta');
  if(tab==='tools'){
    const rows=C.tools.map((t,i)=>({t,...A.T[i]})).filter(r=>r.n).sort((a,b)=>b.n-a.n);
    meta.textContent=rows.length+' tools in selection';
    w.innerHTML='<table><thead><tr><th>Tool</th><th>Category</th><th style="text-align:right">Calls</th>'+
      '<th style="text-align:right">Errors</th><th style="text-align:right">Err&nbsp;%</th>'+
      '<th style="text-align:right">Mean&nbsp;ms</th><th style="text-align:right">Output</th></tr></thead><tbody>'+
      rows.map(r=>{
        const er=pct(r.e,r.n);
        return '<tr><td class="m">'+esc(r.t.n)+'</td><td>'+pill(catOf(r.t.c),CATLBL[catOf(r.t.c)])+
        '</td><td class="n">'+fmt(r.n)+'</td><td class="n">'+fmt(r.e)+'</td><td class="n">'+
        (er>8?'<b style="color:var(--critical)">':'')+p1(er)+(er>8?'</b>':'')+'</td><td class="n">'+
        (r.dn?fmt(Math.round(r.ds/r.dn)):'—')+'</td><td class="n">'+bytes(r.ob)+'</td></tr>';}).join('')+
      '</tbody></table>';
  } else if(tab==='errors'){
    const rows=C.errKinds.map((k,i)=>({k,n:A.K[i]})).filter(r=>r.n).sort((a,b)=>b.n-a.n);
    meta.textContent=fmt(A.e)+' errors · '+rows.length+' distinct kinds';
    w.innerHTML='<table><thead><tr><th>Error kind</th><th>Root cause</th><th style="text-align:right">Count</th>'+
      '<th style="text-align:right">% of errors</th><th style="text-align:right">% of all calls</th></tr></thead><tbody>'+
      rows.map(r=>'<tr><td class="m">'+esc(KINDLBL[r.k.k]||r.k.k)+'</td><td>'+
        pillG(r.k.g)+'</td><td class="n">'+fmt(r.n)+'</td><td class="n">'+p1(pct(r.n,A.e))+
        '</td><td class="n">'+p2(pct(r.n,A.n))+'</td></tr>').join('')+'</tbody></table>';
  } else if(tab==='queries'){
    const rows=C.H.filter(([q,p,d])=>inF(d,p)).sort((a,b)=>b[3]-a[3]);
    meta.textContent=rows.length+' distinct search queries';
    w.innerHTML=rows.length?'<table><thead><tr><th class="qtxt">Query</th><th>Project</th><th>Date</th>'+
      '<th style="text-align:right">Links</th></tr></thead><tbody>'+
      rows.map(([q,p,d,n])=>'<tr><td>'+esc(q)+'</td><td class="m" style="color:var(--muted)">'+
        esc(C.projects[p].n)+'</td><td class="m" style="color:var(--muted)">'+C.dates[d]+
        '</td><td class="n">'+n+'</td></tr>').join('')+'</tbody></table>'
      :'<div class="empty">No searches in this selection.</div>';
  } else if(tab==='urls'){
    const rows=C.I.filter(([u,p])=>sel.has(p)).sort((a,b)=>b[2]-a[2]);
    meta.textContent='top '+rows.length+' by fetch count · project filter only';
    w.innerHTML=rows.length?'<table><thead><tr><th>URL</th><th>Project</th><th style="text-align:right">Fetches</th></tr></thead><tbody>'+
      rows.map(([u,p,n])=>'<tr><td class="m" style="word-break:break-all">'+esc(u)+
        '</td><td class="m" style="color:var(--muted)">'+esc(C.projects[p].n)+'</td><td class="n">'+n+'</td></tr>').join('')+
      '</tbody></table>':'<div class="empty">No fetches in this selection.</div>';
  } else {
    const tot=C.git.reduce((a,g)=>a+g[1],0);
    meta.textContent=fmt(C.meta.gitInvocations)+' git invocations · whole corpus, not filtered';
    w.innerHTML='<table><thead><tr><th>Subcommand</th><th style="text-align:right">Invocations</th>'+
      '<th style="text-align:right">Share</th><th>Mode</th></tr></thead><tbody>'+
      C.git.map(([k,n])=>{
        const readOnly=['status','log','diff','show','rev-parse','branch'].includes(k);
        return '<tr><td class="m">git '+k+'</td><td class="n">'+fmt(n)+'</td><td class="n">'+
        p1(pct(n,C.meta.gitInvocations))+'</td><td>'+
        '<span class="pill" style="background:var(--sunken);color:var(--ink-2)"><span class="dot" style="background:'+
        (readOnly?'var(--s1)':'var(--s2)')+'"></span>'+(readOnly?'inspect':'mutate')+'</span></td></tr>';}).join('')+
      '</tbody></table>';
  }
}
const pill = (c,l) => '<span class="pill" style="background:var(--sunken);color:var(--ink-2)">'+
  '<span class="dot" style="background:var('+CATCOL[c]+')"></span>'+l+'</span>';
const pillG = g => '<span class="pill" style="background:var(--sunken);color:var(--ink-2)">'+
  '<span class="dot" style="background:var('+GRPCOL[g]+')"></span>'+(GRPLBL[g]||g)+'</span>';


/* ---- latency ---- */
let latMode='tool';
function histPctl(counts, q){
  const E=C.latEdges, tot=counts.reduce((a,b)=>a+b,0);
  if(!tot) return null;
  const target=q*tot; let acc=0;
  for(let i=0;i<counts.length;i++){
    if(acc+counts[i]>=target){
      const lo=E[i], hi=(i+1<E.length)?E[i+1]:E[E.length-1]*2;
      return lo+(hi-lo)*(counts[i]?(target-acc)/counts[i]:0);
    }
    acc+=counts[i];
  }
  return E[E.length-1];
}
const msf = v => v==null ? '—'
  : v<1000 ? Math.round(v)+' ms'
  : v<60000 ? (v/1000).toFixed(1)+' s'
  : v<3600000 ? (v/60000).toFixed(1)+' min' : (v/3600000).toFixed(1)+' h';
const edgeLbl = v => {
  if(v===0) return '0';
  if(v<1000) return v+'ms';
  if(v<60000){ const s=v/1000; return (s<10?+s.toFixed(1):Math.round(s))+'s'; }
  if(v<3600000){ const m=v/60000; return (m<10?+m.toFixed(1):Math.round(m))+'m'; }
  return +(v/3600000).toFixed(1)+'h';
};

function drawLatency(A){
  const isTool = latMode==='tool';
  const counts = isTool ? A.LT : A.LM;
  const tot = counts.reduce((a,b)=>a+b,0);
  document.getElementById('note-lat').textContent = isTool ? C.copy.latTool : C.copy.latTurn;
  document.getElementById('lat-meta').textContent = tot
    ? fmt(tot)+(isTool?' timed calls':' machine-triggered turns') : 'nothing timed';

  /* histogram */
  const E=C.latEdges, W=560, H=176, PL=34, PB=30, max=Math.max(...counts,1);
  let s=`<svg viewBox="0 0 ${W} ${H+PB}" role="img" aria-label="Latency distribution">`;
  const bw=(W-PL-6)/counts.length;
  const p50=histPctl(counts,.5), p95=histPctl(counts,.95);
  for(let i=0;i<counts.length;i++){
    const h=(H-14)*counts[i]/max, x=PL+i*bw;
    s+=`<rect x="${(x+1).toFixed(1)}" y="${(H-h).toFixed(1)}" width="${(bw-2).toFixed(1)}" `+
       `height="${Math.max(counts[i]?1:0,h).toFixed(1)}" fill="var(${isTool?'--s1':'--s7'})" rx="1.5"/>`;
    if(i%4===0) s+=`<text class="ax" x="${(x).toFixed(1)}" y="${H+13}" text-anchor="middle">${edgeLbl(E[i])}</text>`;
  }
  for(const [v,lbl] of [[p50,'p50'],[p95,'p95']]){
    if(v==null) continue;
    let bi=0; while(bi+1<E.length && E[bi+1]<=v) bi++;
    const frac=(E[bi+1]?(v-E[bi])/(E[bi+1]-E[bi]):0);
    const x=PL+(bi+Math.min(1,Math.max(0,frac)))*bw;
    s+=`<line x1="${x.toFixed(1)}" x2="${x.toFixed(1)}" y1="4" y2="${H}" stroke="var(--critical)" stroke-width="1.5" stroke-dasharray="3 2"/>`;
    s+=`<text class="dl" x="${(x+4).toFixed(1)}" y="12">${lbl} ${msf(v)}</text>`;
  }
  s+=`<line class="bl-axis" x1="${PL}" x2="${W}" y1="${H+.5}" y2="${H+.5}"/>`;
  s+=`<text class="ax" x="${PL-6}" y="12" text-anchor="end">${fmt(max)}</text>`;
  s+=`<text class="ax" x="${PL-6}" y="${H+3}" text-anchor="end">0</text></svg>`;
  const hh=document.getElementById('lat-hist'); hh.innerHTML=s;
  hh.querySelectorAll('rect').forEach((r,i)=>bindTip(r,
    `<b>${edgeLbl(E[i])} – ${i+1<E.length?edgeLbl(E[i+1]):'∞'}</b>`+
    `<div class="r"><i>count</i><b>${fmt(counts[i])}</b></div>`+
    `<div class="r"><i>share</i><b>${p1(pct(counts[i],tot))}</b></div>`));

  document.getElementById('lat-stats').innerHTML=
    [['p50',.5],['p90',.9],['p95',.95],['p99',.99]].map(([k,q])=>{
      const v=histPctl(counts,q);
      return '<div class="latstat'+(q>=.95?' hi':'')+'"><span class="k">'+k+
        '</span><span class="v">'+msf(v)+'</span></div>';}).join('')+
    (isTool?'':'<div class="latstat"><span class="k">out tok/s</span><span class="v">'+
      (A.turnSecs?(A.turnOut/A.turnSecs).toFixed(1):'—')+'</span></div>'+
     '<div class="latstat"><span class="k">cache hit</span><span class="v">'+
      p1(pct(A.cacheRead,A.cacheRead+A.cacheFresh))+'</span></div>');

  /* per-tool / per-model p50 -> p95, log axis */
  const rows=[];
  if(isTool){
    C.tools.forEach((t,i)=>{ const c=A.LTby[i], n=c.reduce((a,b)=>a+b,0);
      if(n>=5) rows.push({label:t.n,n,p50:histPctl(c,.5),p95:histPctl(c,.95),
                          color:'var('+CATCOL[catOf(t.c)]+')'}); });
  } else {
    (C.models||[]).forEach((m,i)=>{ const c=A.LMby[i], n=c.reduce((a,b)=>a+b,0);
      if(n>=5) rows.push({label:m,n,p50:histPctl(c,.5),p95:histPctl(c,.95),
                          color:'var(--s7)'}); });
  }
  rows.sort((a,b)=>b.p50-a.p50);
  drawLatRanges(rows.slice(0,14));
}

const TICKS=[[1,'1ms'],[10,'10ms'],[100,'100ms'],[1000,'1s'],[10000,'10s'],
             [60000,'1min'],[600000,'10min'],[3600000,'1h']];
function drawLatRanges(rows){
  const host=document.getElementById('lat-bars');
  if(!rows.length){ host.innerHTML='<div class="empty">Nothing timed in this selection.</div>'; return; }
  const LO=1, HI=Math.max(...rows.map(r=>r.p95||1),1000);
  const l10=Math.log10, span=l10(HI)-l10(LO)||1;
  const W=700, GUT=132, RH=23, PB=22, H=rows.length*RH+PB;
  const x=v=>GUT+(W-GUT-56)*(l10(Math.max(v||LO,LO))-l10(LO))/span;
  let s=`<svg viewBox="0 0 ${W} ${H+8}" role="img" aria-label="Median to 95th percentile latency by tool, log scale">`;
  for(const [v,lbl] of TICKS){
    if(v>HI*1.05) continue;
    s+=`<line class="gl" x1="${x(v).toFixed(1)}" x2="${x(v).toFixed(1)}" y1="0" y2="${rows.length*RH}"/>`;
    s+=`<text class="ax" x="${x(v).toFixed(1)}" y="${rows.length*RH+13}" text-anchor="middle">${lbl}</text>`;
  }
  rows.forEach((r,i)=>{
    const y=i*RH+RH/2, a=x(r.p50), b=x(r.p95);
    s+=`<text class="ax" x="${GUT-9}" y="${y+3.5}" text-anchor="end" style="font-size:11px;fill:var(--ink-2)">${esc(r.label).slice(0,20)}</text>`;
    s+=`<line x1="${a.toFixed(1)}" x2="${Math.max(b,a+2).toFixed(1)}" y1="${y}" y2="${y}" stroke="var(--axis)" stroke-width="2" stroke-linecap="round"/>`;
    s+=`<circle cx="${Math.max(b,a+2).toFixed(1)}" cy="${y}" r="3" fill="var(--axis)"/>`;
    s+=`<circle cx="${a.toFixed(1)}" cy="${y}" r="4.5" fill="${r.color}" stroke="var(--surface)" stroke-width="2"/>`;
    s+=`<text class="ax" x="${W-50}" y="${y+3.5}" style="font-size:10.5px;fill:var(--ink)">${msf(r.p50)}</text>`;
  });
  s+='</svg>';
  host.innerHTML=s;
  host.querySelectorAll('circle').forEach((c,i)=>{
    const r=rows[Math.floor(i/2)]; if(!r) return;
    bindTip(c,'<b>'+esc(r.label)+'</b><div class="r"><i>timed</i><b>'+fmt(r.n)+'</b></div>'+
      '<div class="r"><i>p50</i><b>'+msf(r.p50)+'</b></div>'+
      '<div class="r"><i>p95</i><b>'+msf(r.p95)+'</b></div>');
  });
}
document.querySelector('.lat-switch').addEventListener('click',e=>{
  const b=e.target.closest('[data-lat]'); if(!b) return;
  latMode=b.dataset.lat;
  document.querySelectorAll('[data-lat]').forEach(x=>
    x.setAttribute('aria-pressed', x===b?'true':'false'));
  render();
});

/* ---- render ---- */
function render(){
  const A=agg();
  const setText=(id,v)=>{const el=document.getElementById(id); if(el&&v) el.textContent=v;};
  setText('thesis',C.copy.thesis); setText('note-timeline',C.copy.timeline);
  setText('note-tools',C.copy.tools); setText('note-bash',C.copy.bash);
  const real=A.e-A.notReal;
  document.getElementById('scope').innerHTML= (sel.size===nP?'all projects':sel.size+' of '+nP+' projects')+
    ' · <b>'+C.dates[d0]+'</b> → <b>'+C.dates[d1]+'</b> · '+(d1-d0+1)+' days';
  document.getElementById('window').innerHTML=
    '<b>'+fmt(C.meta.totalCalls)+'</b> tool calls<br><b>'+fmt(C.meta.transcripts)+'</b> transcripts · <b>'+
    fmt(C.meta.totalSessions)+'</b> sessions<br>'+C.meta.firstDate+' → '+C.meta.lastDate;

  /* KPIs */
  document.getElementById('kpis').innerHTML=[
    ['Tool calls',fmt(A.n),'across <em>'+fmt(A.sessions)+'</em> sessions'],
    ['Genuine failure rate',p2(pct(real,A.n)),fmt(real)+' real · <em>'+p2(pct(A.e,A.n))+' raw incl. guardrails</em>'],
    ['Blocked by your own hooks',fmt(A.notReal),p1(pct(A.notReal,A.e||1))+' of all logged errors'],
    ['Issued by subagents',p1(pct(A.side,A.n)),fmt(A.side)+' of '+fmt(A.n)+' calls'],
    ['Result payload',bytes(A.ob),'<em>'+bytes(A.ib)+'</em> of input sent'],
  ].map(([k,v,s])=>'<div class="kpi"><span class="k">'+k+'</span><span class="v">'+v+
    '</span><span class="sub">'+s+'</span></div>').join('');

  /* timeline */
  drawTimeline(A);
  document.getElementById('tl-meta').textContent=fmt(A.n)+' calls over '+(d1-d0+1)+' days';
  document.getElementById('tl-legend').innerHTML=STACK.filter(c=>A.cat[c]).map(c=>
    '<span class="lgi"><span class="sw" style="background:var('+CATCOL[c]+')"></span>'+CATLBL[c]+
    ' <b>'+fmt(A.cat[c])+'</b></span>').join('')+
    '<span class="lgi"><span class="sw" style="background:var(--critical)"></span>Error rate</span>';

  /* tools */
  const tr=C.tools.map((t,i)=>({t,...A.T[i]})).filter(r=>r.n).sort((a,b)=>b.n-a.n).slice(0,14);
  barList(document.getElementById('tools'), tr.map(r=>({
    label:r.t.n, v:r.n-r.e, v2:r.e||null,
    color:'var('+CATCOL[catOf(r.t.c)]+')', color2:'var(--critical)',
    right:fmt(r.n)+(r.e?' <i>'+p1(pct(r.e,r.n))+'</i>':''),
    tip:'<b>'+esc(r.t.n)+'</b><div class="r"><i>calls</i><b>'+fmt(r.n)+'</b></div>'+
        '<div class="r"><i>errors</i><b>'+fmt(r.e)+' · '+p1(pct(r.e,r.n))+'</b></div>'+
        '<div class="r"><i>mean</i><b>'+(r.dn?fmt(Math.round(r.ds/r.dn))+' ms':'—')+'</b></div>'+
        '<div class="r"><i>output</i><b>'+bytes(r.ob)+'</b></div>'
  })));
  document.getElementById('tools-meta').textContent=tr.length+' of '+C.tools.filter((t,i)=>A.T[i].n).length+' shown';

  /* failures */
  const gr=GRPS.map(g=>({g,n:A.G[g]})).filter(r=>r.n);
  const fc=document.getElementById('fail-comp');
  fc.innerHTML=gr.length?gr.map(r=>{
    const sh=100*r.n/A.e;
    return '<span data-g="'+r.g+'" style="flex:'+r.n+';background:var('+GRPCOL[r.g]+')">'+
      (sh>9?p1(sh):'')+'</span>';}).join(''):'';
  fc.querySelectorAll('span').forEach(s=>{
    const g=s.dataset.g, n=A.G[g];
    bindTip(s,'<b>'+GRPLBL[g]+'</b><div class="r"><i>errors</i><b>'+fmt(n)+'</b></div>'+
      '<div class="r"><i>of all errors</i><b>'+p1(pct(n,A.e))+'</b></div>'+
      '<div class="r"><i>of all calls</i><b>'+p2(pct(n,A.n))+'</b></div>'+
      (NOTREAL.has(g)?'<div style="height:5px"></div><i>not a tool defect</i>':''));
  });
  document.getElementById('fail-legend').innerHTML=gr.map(r=>
    '<span class="lgi"><span class="sw" style="background:var('+GRPCOL[r.g]+')"></span>'+GRPLBL[r.g]+
    ' <b>'+fmt(r.n)+'</b></span>').join('')||'<span class="lgi">No errors in this selection.</span>';
  document.getElementById('fail-meta').textContent=fmt(A.e)+' errors · '+p2(pct(A.e,A.n))+' of calls';
  const kr=C.errKinds.map((k,i)=>({k,n:A.K[i]})).filter(r=>r.n).sort((a,b)=>b.n-a.n).slice(0,9);
  barList(document.getElementById('fail-kinds'), kr.map(r=>({
    label:KINDLBL[r.k.k]||r.k.k, v:r.n, color:'var('+GRPCOL[r.k.g]+')',
    right:fmt(r.n)+' <i>'+p1(pct(r.n,A.e))+'</i>',
    tip:'<b>'+esc(KINDLBL[r.k.k]||r.k.k)+'</b><div class="r"><i>root cause</i><b>'+GRPLBL[r.k.g]+
      '</b></div><div class="r"><i>count</i><b>'+fmt(r.n)+'</b></div>'
  })));

  /* bash */
  const br=C.bins.map((b,i)=>({b,...A.B[i]})).filter(r=>r.n&&r.b!=='· other')
    .sort((a,b)=>b.n-a.n).slice(0,16);
  barList(document.getElementById('bash'), br.map(r=>({
    label:r.b, v:r.n, color:'var(--s1)',
    right:p1(pct(r.n,A.bashCalls))+' <i>'+fmt(r.n)+'</i>',
    tip:'<b>'+esc(r.b)+'</b><div class="r"><i>Bash calls using it</i><b>'+fmt(r.n)+'</b></div>'+
      '<div class="r"><i>share of Bash</i><b>'+p1(pct(r.n,A.bashCalls))+'</b></div>'+
      '<div class="r"><i>calls that errored</i><b>'+fmt(r.e)+' · '+p1(pct(r.e,r.n))+'</b></div>'
  })));
  document.getElementById('bash-meta').textContent=fmt(A.bashCalls)+' Bash calls';

  /* web */
  const wr=C.domains.map((d,i)=>({d,s:A.W[i][0],f:A.W[i][1]})).filter(r=>(r.s+r.f)&&r.d!=='· other')
    .sort((a,b)=>(b.s+b.f)-(a.s+a.f)).slice(0,14);
  barList(document.getElementById('web'), wr.map(r=>({
    label:r.d, v:r.s, v2:r.f, color:'var(--s1)', color2:'var(--s2)',
    right:fmt(r.s+r.f),
    tip:'<b>'+esc(r.d)+'</b><div class="r"><i>search results</i><b>'+fmt(r.s)+'</b></div>'+
      '<div class="r"><i>pages fetched</i><b>'+fmt(r.f)+'</b></div>'
  })));
  const ws=wr.reduce((a,r)=>a+r.s,0), wf=wr.reduce((a,r)=>a+r.f,0);
  document.getElementById('web-legend').innerHTML=
    '<span class="lgi"><span class="sw" style="background:var(--s1)"></span>Search results <b>'+fmt(ws)+'</b></span>'+
    '<span class="lgi"><span class="sw" style="background:var(--s2)"></span>Pages fetched <b>'+fmt(wf)+'</b></span>';
  document.getElementById('web-meta').textContent=wr.length?wr.length+' domains shown':'no web activity';

  drawLatency(A);

  /* hours + exts */
  drawHours(A);
  const xr=C.exts.map((x,i)=>({x,r:A.X[i][0],w:A.X[i][1]})).filter(r=>(r.r+r.w)&&r.x!=='· other')
    .sort((a,b)=>(b.r+b.w)-(a.r+a.w)).slice(0,12);
  barList(document.getElementById('exts'), xr.map(r=>({
    label:r.x, v:r.r, v2:r.w, color:'var(--s2)', color2:'var(--s3)',
    right:fmt(r.r+r.w),
    tip:'<b>'+esc(r.x)+'</b><div class="r"><i>reads</i><b>'+fmt(r.r)+'</b></div>'+
      '<div class="r"><i>writes / edits</i><b>'+fmt(r.w)+'</b></div>'
  })));
  document.getElementById('ext-legend').innerHTML=
    '<span class="lgi"><span class="sw" style="background:var(--s2)"></span>Read <b>'+
      fmt(xr.reduce((a,r)=>a+r.r,0))+'</b></span>'+
    '<span class="lgi"><span class="sw" style="background:var(--s3)"></span>Written / edited <b>'+
      fmt(xr.reduce((a,r)=>a+r.w,0))+'</b></span>';
  document.getElementById('ext-meta').textContent=fmt(xr.reduce((a,r)=>a+r.r+r.w,0))+' file touches';

  drawTable(A);
}

function drawFoot(){
  const m=C.meta, li=[];
  li.push('Source: <code>'+(m.redacted?'&lt;redacted&gt;':'~/.claude/projects/**/*.jsonl')+
    '</code> — '+fmt(m.transcripts)+' transcripts across '+m.projects+' projects, parsed into '+
    fmt(m.totalCalls)+' tool-call rows and '+fmt(m.uniqUrls)+' URL rows.');
  li.push('<b>Genuine failure rate</b> excludes <code>blocked_by_policy</code> and '+
    '<code>hook_infra</code> — hook denials, auto-mode permission blocks and '+
    '<code>PreToolUse</code> hook timeouts. '+C.copy.genuine);
  li.push('Bash shares sum past 100%: one call often runs several commands. Heredoc bodies and '+
    'quoted strings are stripped first, so embedded scripts are not counted as shell. '+
    fmt(m.heredocCalls)+' of '+fmt(m.bashCalls)+' Bash calls carried a heredoc.');
  li.push('Duration is request&nbsp;→&nbsp;result wall clock, so <code>AskUserQuestion</code> '+
    'measures you being away, not tool latency. It is excluded from the aggregate mean.');
  if(m.gitInvocations) li.push('Git subcommands are counted across the whole corpus by regex and '+
    'do not respond to the filters.');
  li.push('Generated '+m.generated+' by cc-toolstat v'+m.version+
    (m.redacted?' with <code>--redact</code>':'')+'. Local files only; nothing was uploaded.');
  document.getElementById('foot').innerHTML=
    '<div class="eyebrow" style="margin-bottom:9px">Provenance &amp; caveats</div><ul>'+
    li.map(x=>'<li>'+x+'</li>').join('')+'</ul>';
}
drawFoot();
if(!C.git.length){ const g=document.getElementById('tab-git'); if(g) g.remove(); }

/* ---- controls ---- */
const projTotals=C.projects.map(()=>0);
for(const [d,p,t,n] of C.A) projTotals[p]+=n;
const SHOWN=10; let chipsOpen=false;
function chipHTML(i){const p=C.projects[i];
  return '<button class="chip" data-p="'+i+'" aria-pressed="true" title="'+esc(p.k)+'">'+esc(p.n)+
  '<span class="cn">'+(projTotals[i]>=1000?(projTotals[i]/1000).toFixed(1)+'k':projTotals[i])+'</span></button>';}
function drawChips(){
  const n=chipsOpen?nP:Math.min(SHOWN,nP);
  let h=C.projects.slice(0,n).map((_,i)=>chipHTML(i)).join('');
  if(nP>SHOWN) h+='<button class="btn" id="more">'+(chipsOpen?'fewer':'+'+(nP-SHOWN)+' smaller')+'</button>';
  document.getElementById('chips').innerHTML=h; syncChips();
}
drawChips();
document.getElementById('chips').addEventListener('click',e=>{
  if(e.target.closest('#more')){ chipsOpen=!chipsOpen; drawChips(); return; }
  const b=e.target.closest('.chip'); if(!b) return;
  const i=+b.dataset.p;
  if(sel.size===nP){ sel=new Set([i]); if(i>=SHOWN) chipsOpen=true; }
  else if(sel.has(i)){ sel.delete(i); if(!sel.size) sel=new Set(C.projects.map((_,j)=>j)); }
  else sel.add(i);
  drawChips(); render();
});
function syncChips(){
  document.querySelectorAll('.chip').forEach(b=>
    b.setAttribute('aria-pressed', sel.has(+b.dataset.p)?'true':'false'));
}
const months=[...new Set(C.dates.map(d=>d.slice(0,7)))];
const MN=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
document.getElementById('ranges').innerHTML=
  '<button class="btn" data-range="all">All '+nD+' days</button>'+
  months.map(m=>'<button class="btn" data-range="'+m+'">'+MN[+m.slice(5,7)-1]+
    (months.length>12?" '"+m.slice(2,4):'')+'</button>').join('')+
  (nD>7?'<button class="btn" data-range="last7">Last 7 active</button>':'');
document.getElementById('ranges').addEventListener('click',e=>{
  const b=e.target.closest('[data-range]'); if(!b) return;
  const r=b.dataset.range;
  if(r==='all'){ d0=0; d1=nD-1; }
  else if(r==='last7'){ d1=nD-1; d0=Math.max(0,nD-7); }
  else{
    const idx=C.dates.map((d,i)=>d.startsWith(r)?i:-1).filter(i=>i>=0);
    if(idx.length){ d0=idx[0]; d1=idx[idx.length-1]; }
  }
  render();
});
document.getElementById('reset').addEventListener('click',()=>{
  sel=new Set(C.projects.map((_,i)=>i)); d0=0; d1=nD-1; chipsOpen=false; drawChips(); render();
});
document.getElementById('tabs').addEventListener('click',e=>{
  const b=e.target.closest('.tab'); if(!b) return;
  tab=b.dataset.tab;
  document.querySelectorAll('.tab').forEach(t=>t.setAttribute('aria-selected', t===b?'true':'false'));
  render();
});
addEventListener('scroll',hideTip,{passive:true});
render();
})();
</script>
"""


# ------------------------------------------------------------------ report ---

def _table(headers, rows, aligns=None, indent="  "):
    if not rows:
        return indent + "(none)\n"
    cols = list(zip(*([headers] + [[str(c) for c in r] for r in rows])))
    w = [max(len(str(c)) for c in col) for col in cols]
    aligns = aligns or ["<"] + [">"] * (len(headers) - 1)
    out = [indent + "  ".join(("{:%s%d}" % (aligns[i], w[i])).format(h)
                              for i, h in enumerate(headers)).rstrip()]
    out.append(indent + "  ".join("-" * x for x in w))
    for r in rows:
        out.append(indent + "  ".join(("{:%s%d}" % (aligns[i], w[i])).format(str(c))
                                      for i, c in enumerate(r)).rstrip())
    return "\n".join(out) + "\n"


def write_report(calls, urls, turns, cube, git_counter, path):
    live = [r for r in calls if r.get("date")]
    n = len(live)
    pc = lambda a, b: "%.2f%%" % (100.0 * a / b) if b else "—"
    p1 = lambda a, b: "%.1f%%" % (100.0 * a / b) if b else "—"
    err = [r for r in live if r["is_error"]]
    real = [r for r in err if r["error_group"] not in NOT_REAL]
    m = cube["meta"]
    o = []
    o.append("=" * 78 + "\ncc-toolstat v%s — %s\n" % (__version__, m["generated"]) + "=" * 78)
    o.append("""
tool calls        : {calls}
sessions          : {sess}
projects          : {proj}
transcripts       : {tr}
distinct tools    : {tools}
window            : {a} -> {b}  ({ad} active of {cd} calendar days)
errors            : {e}  ({ep})
genuine failures  : {re}  ({rep})   [excludes hook + policy blocks]
subagent-issued   : {side}  ({sidep})
payload           : {bi} in / {bo} out
""".format(calls=fmt_int(n), sess=fmt_int(m["totalSessions"]), proj=m["projects"],
           tr=fmt_int(m["transcripts"]), tools=len(cube["tools"]),
           a=m["firstDate"], b=m["lastDate"], ad=m["activeDays"], cd=m["calendarDays"],
           e=fmt_int(len(err)), ep=pc(len(err), n),
           re=fmt_int(len(real)), rep=pc(len(real), n),
           side=fmt_int(sum(1 for r in live if r["is_sidechain"])),
           sidep=p1(sum(1 for r in live if r["is_sidechain"]), n),
           bi=_bytes(m["bytesIn"]), bo=_bytes(m["bytesOut"])).rstrip())

    def section(title):
        o.append("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)

    section("TOOL CATEGORY")
    cat = defaultdict(lambda: [0, 0, set()])
    for r in live:
        c = cat[r["tool_category"]]
        c[0] += 1
        c[1] += 1 if r["is_error"] else 0
        c[2].add(r["tool_name"])
    o.append(_table(["category", "calls", "share", "tools", "errors", "err%"],
                    [[k, fmt_int(v[0]), p1(v[0], n), len(v[2]), fmt_int(v[1]), p1(v[1], v[0])]
                     for k, v in sorted(cat.items(), key=lambda x: -x[1][0])]))

    section("TOOL COUNT")
    tl = defaultdict(lambda: [0, 0, 0, 0, set()])
    for r in live:
        t = tl[r["tool_name"]]
        t[0] += 1
        t[1] += 1 if r["is_error"] else 0
        if r["duration_ms"] is not None:
            t[2] += r["duration_ms"]
            t[3] += 1
        t[4].add(r["session_id"])
    o.append(_table(["tool", "category", "calls", "sessions", "errors", "err%", "mean ms"],
                    [[k, CATEGORY.get(k, "mcp" if k.startswith("mcp__") else "other"),
                      fmt_int(v[0]), len(v[4]), fmt_int(v[1]), p1(v[1], v[0]),
                      fmt_int(v[2] // v[3]) if v[3] else "—"]
                     for k, v in sorted(tl.items(), key=lambda x: -x[1][0])]))

    section("FAILURES")
    if err:
        g = Counter(r["error_group"] for r in err)
        o.append("root cause\n")
        o.append(_table(["group", "n", "% of errors", "% of all calls"],
                        [[k, fmt_int(v), p1(v, len(err)), pc(v, n)] for k, v in g.most_common()]))
        k = Counter(r["error_kind"] for r in err)
        o.append("\nerror kind\n")
        o.append(_table(["kind", "group", "n", "% of errors"],
                        [[kk, ERROR_GROUP.get(kk, "other"), fmt_int(v), p1(v, len(err))]
                         for kk, v in k.most_common()]))
        o.append("\nfailure rate by tool (>=20 calls)\n")
        o.append(_table(["tool", "calls", "errors", "err%"],
                        sorted([[t, fmt_int(v[0]), fmt_int(v[1]), p1(v[1], v[0])]
                                for t, v in tl.items() if v[0] >= 20 and v[1]],
                               key=lambda r: -float(r[3][:-1]))))
        bb = defaultdict(lambda: [0, 0])
        for r in live:
            if r["tool_name"] == "Bash":
                for b in r["bash_bins"] or []:
                    bb[b][0] += 1
                    bb[b][1] += 1 if r["is_error"] else 0
        rows = sorted([[b, fmt_int(v[0]), fmt_int(v[1]), p1(v[1], v[0])]
                       for b, v in bb.items() if v[0] >= 20 and v[1]],
                      key=lambda r: -float(r[3][:-1]))[:12]
        if rows:
            o.append("\ncommands present in the most failing Bash calls (>=20 calls)\n")
            o.append(_table(["command", "calls using", "of which errored", "rate"], rows))
    else:
        o.append("  no errors recorded\n")

    section("LATENCY")
    o.append("""  Two clocks, measured separately:
    tool latency  tool_use emitted -> tool_result recorded. Includes the command
                  itself plus, when a call needed approval, however long you took
                  to grant it. Percentiles are robust to that; the mean is not.
    turn latency  triggering tool_result -> last block of the model's reply, for
                  inferences the harness started on its own. Turns triggered by a
                  typed prompt are excluded: that gap contains your typing.
""")
    tool_lat = defaultdict(list)
    for r in live:
        if r["duration_ms"] is not None:
            tool_lat[r["tool_name"]].append(r["duration_ms"])
    allv = sorted(v for vals in tool_lat.values() for v in vals)
    if allv:
        o.append("  all tool calls (%s timed): p50 %s · p90 %s · p95 %s · p99 %s · max %s\n"
                 % (fmt_int(len(allv)), ms(pctl(allv, .50)), ms(pctl(allv, .90)),
                    ms(pctl(allv, .95)), ms(pctl(allv, .99)), ms(allv[-1])))
        rows = []
        for t, vals in sorted(tool_lat.items(), key=lambda x: -pctl(sorted(x[1]), .5)):
            v = sorted(vals)
            if len(v) < 5:
                continue
            rows.append([t, fmt_int(len(v)), ms(pctl(v, .5)), ms(pctl(v, .9)),
                         ms(pctl(v, .95)), ms(v[-1]),
                         ms(sum(v) / len(v))])
        o.append("\n  by tool, slowest median first (>=5 timed calls)\n")
        o.append(_table(["tool", "n", "p50", "p90", "p95", "max", "mean"], rows))

        cat_lat = defaultdict(list)
        for r in live:
            if r["duration_ms"] is not None:
                cat_lat[r["tool_category"]].append(r["duration_ms"])
        o.append("\n  by category\n")
        o.append(_table(["category", "n", "p50", "p90", "p95"],
                        [[c, fmt_int(len(v)), ms(pctl(sorted(v), .5)),
                          ms(pctl(sorted(v), .9)), ms(pctl(sorted(v), .95))]
                         for c, v in sorted(cat_lat.items(),
                                            key=lambda x: -pctl(sorted(x[1]), .5))]))

        bash_lat = defaultdict(list)
        for r in live:
            if r["tool_name"] == "Bash" and r["duration_ms"] is not None:
                for b in r["bash_bins"] or []:
                    bash_lat[b].append(r["duration_ms"])
        rows = [[b, fmt_int(len(v)), ms(pctl(sorted(v), .5)), ms(pctl(sorted(v), .9)),
                 ms(max(v))]
                for b, v in sorted(bash_lat.items(), key=lambda x: -pctl(sorted(x[1]), .5))
                if len(v) >= 20][:15]
        if rows:
            o.append("\n  Bash calls containing each command, slowest median first (>=20 calls)\n")
            o.append(_table(["command", "calls", "p50", "p90", "max"], rows))

        plabels = shorten_projects(sorted({r["project"] for r in live}))
        slow = sorted((r for r in live if r["duration_ms"] is not None),
                      key=lambda r: -r["duration_ms"])[:10]
        o.append("\n  slowest individual calls\n")
        o.append(_table(["tool", "duration", "project", "when"],
                        [[r["tool_name"], ms(r["duration_ms"]),
                          plabels[r["project"]][:28],
                          (r["ts"] or "")[:16].replace("T", " ")] for r in slow]))
    else:
        o.append("  no timed tool calls\n")

    idle_turns = [t for t in turns if t.get("idle")]
    timed = [t for t in turns if t.get("latency_ms") is not None
             and t.get("trigger_kind") == "tool_result" and not t.get("idle")]
    if timed:
        lv = sorted(t["latency_ms"] for t in timed)
        o.append("\n  model turn latency (%s of %s turns machine-triggered; %s excluded as "
                 "idle, i.e. the trigger sat more than %s in the past because the session was "
                 "paused, interrupted or resumed)\n"
                 % (fmt_int(len(timed)), fmt_int(len(turns)), fmt_int(len(idle_turns)),
                    ms(IDLE_CUTOFF_MS)))
        rows = []
        by_model = defaultdict(list)
        for t in timed:
            by_model[t.get("model") or "?"].append(t)
        for mdl, ts_ in sorted(by_model.items(), key=lambda x: -len(x[1])):
            v = sorted(t["latency_ms"] for t in ts_)
            out = sum(t["output_tokens"] for t in ts_)
            secs = sum(t["latency_ms"] for t in ts_) / 1000.0
            med_out = pctl(sorted(t["output_tokens"] for t in ts_), .5)
            rows.append([mdl, fmt_int(len(v)), ms(pctl(v, .5)), ms(pctl(v, .9)),
                         ms(pctl(v, .95)), ms(v[-1]), fmt_int(med_out or 0),
                         "%.1f" % (out / secs) if secs else "—"])
        o.append(_table(["model", "turns", "p50", "p90", "p95", "max",
                         "med out tok", "out tok/s"], rows))
        o.append("  out tok/s is end to end (queue + prefill + decode), so a model used for "
                 "many small turns\n  reads slower than one used for long ones - read it "
                 "next to the median output size.\n")

        tot_out = sum(t["output_tokens"] for t in turns)
        tot_in = sum(t["input_tokens"] for t in turns)
        tot_cr = sum(t["cache_read_tokens"] for t in turns)
        tot_cc = sum(t["cache_creation_tokens"] for t in turns)
        billed = tot_in + tot_cc
        o.append("\n  tokens: %s output · %s fresh input · %s cache read · %s cache write\n"
                 "  cache hit ratio: %.1f%% of context tokens came from cache\n"
                 % (fmt_int(tot_out), fmt_int(tot_in), fmt_int(tot_cr), fmt_int(tot_cc),
                    100.0 * tot_cr / (tot_cr + billed) if (tot_cr + billed) else 0))

        with_think = [t["latency_ms"] for t in timed if t.get("thinking")]
        without = [t["latency_ms"] for t in timed if not t.get("thinking")]
        if with_think and without:
            o.append("  extended thinking: p50 %s over %s turns vs %s over %s without\n"
                     % (ms(pctl(sorted(with_think), .5)), fmt_int(len(with_think)),
                        ms(pctl(sorted(without), .5)), fmt_int(len(without))))

        # Machine time only: human-facing tools are a wait on you, not on a
        # machine, and idle turns are not inference at all.
        tool_ms = sum(r["duration_ms"] for r in live
                      if r["duration_ms"] is not None
                      and r["tool_category"] != "user_io"
                      and r["duration_ms"] <= IDLE_CUTOFF_MS)
        human_ms = sum(r["duration_ms"] for r in live
                       if r["duration_ms"] is not None and r["tool_category"] == "user_io")
        model_ms = sum(t["latency_ms"] for t in timed)
        both = tool_ms + model_ms
        if both:
            o.append("\n  where the machine time goes: %.0f%% waiting on tools, "
                     "%.0f%% waiting on the model\n"
                     "  (%s of tool time, %s of model time; excludes %s of human-facing "
                     "waits and any single wait over %s)\n"
                     % (100.0 * tool_ms / both, 100.0 * model_ms / both,
                        ms(tool_ms), ms(model_ms), ms(human_ms), ms(IDLE_CUTOFF_MS)))

    section("WEB")
    if urls:
        ws = [u for u in urls if u["source"] == "WebSearch"]
        wf = [u for u in urls if u["source"] == "WebFetch"]
        o.append("  %s url rows · %s unique · %s domains\n"
                 "  WebSearch: %s result links from %s distinct queries\n"
                 "  WebFetch : %s requests to %s unique urls\n"
                 % (fmt_int(len(urls)), fmt_int(m["uniqUrls"]), m["uniqDomains"],
                    fmt_int(len(ws)), fmt_int(len({u["query"] for u in ws})),
                    fmt_int(len(wf)), fmt_int(len({u["url"] for u in wf}))))
        dm = defaultdict(lambda: [0, 0])
        for u in urls:
            dm[u["domain"]][0 if u["source"] == "WebSearch" else 1] += 1
        o.append(_table(["domain", "search links", "fetched"],
                        [[k, fmt_int(v[0]), fmt_int(v[1])]
                         for k, v in sorted(dm.items(), key=lambda x: -sum(x[1]))[:25]]))
    else:
        o.append("  no web activity\n")

    section("WORKLOAD")
    bc = Counter()
    for r in live:
        if r["tool_name"] == "Bash":
            for b in r["bash_bins"] or []:
                bc[b] += 1
    if bc:
        o.append("commands by share of Bash calls (%s calls, %s cmds each)\n"
                 % (fmt_int(m["bashCalls"]), m["cmdsPerBash"]))
        o.append(_table(["command", "calls using", "% of bash"],
                        [[k, fmt_int(v), p1(v, m["bashCalls"])] for k, v in bc.most_common(25)]))
    if git_counter:
        o.append("\ngit subcommands (%s invocations)\n" % fmt_int(sum(git_counter.values())))
        o.append(_table(["subcommand", "n", "share"],
                        [[k, fmt_int(v), p1(v, sum(git_counter.values()))]
                         for k, v in git_counter.most_common(12)]))
    ext = defaultdict(lambda: [0, 0])
    for r in live:
        if r["tool_category"] in ("file_read", "file_write"):
            ext[r["file_ext"] or "(none)"][0 if r["tool_category"] == "file_read" else 1] += 1
    if ext:
        o.append("\nfile extensions\n")
        o.append(_table(["ext", "read", "written"],
                        [[k, fmt_int(v[0]), fmt_int(v[1])]
                         for k, v in sorted(ext.items(), key=lambda x: -sum(x[1]))[:16]]))
    pr = defaultdict(lambda: [0, 0, set(), Counter()])
    for r in live:
        p = pr[r["project"]]
        p[0] += 1
        p[1] += 1 if r["is_error"] else 0
        p[2].add(r["session_id"])
        p[3][r["tool_name"]] += 1
    labels = shorten_projects(list(pr))
    o.append("\nprojects\n")
    o.append(_table(["project", "calls", "sessions", "err%", "top tool"],
                    [[labels[k][:44], fmt_int(v[0]), len(v[2]), p1(v[1], v[0]),
                      v[3].most_common(1)[0][0]]
                     for k, v in sorted(pr.items(), key=lambda x: -x[1][0])[:15]]))
    hrs = Counter(r["hour"] for r in live if r["hour"] is not None)
    if hrs:
        peak = max(hrs.values())
        o.append("\nhour of day (local)\n")
        for h in range(24):
            v = hrs.get(h, 0)
            o.append("  %02d:00 %-46s %s" % (h, "#" * int(46 * v / peak), fmt_int(v)))
        o.append("")
    for label, key in (("models", "model"), ("entrypoints", "entrypoint"),
                       ("subagent types", "subagent_type")):
        c = Counter(r[key] for r in live if r.get(key))
        if c:
            o.append("\n%s\n" % label)
            o.append(_table([key, "calls"], [[k, fmt_int(v)] for k, v in c.most_common(10)]))
    sc = Counter(r["session_id"] for r in live)
    if sc:
        vals = sorted(sc.values())
        o.append("\nsession intensity: mean %d · median %d · max %s calls\n"
                 % (sum(vals) / len(vals), vals[len(vals) // 2], fmt_int(vals[-1])))
    text = "\n".join(o) + "\n"
    with open(path, "w") as fh:
        fh.write(text)
    return text


def _bytes(b):
    b = float(b or 0)
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if b >= div:
            return "%.1f %s" % (b / div, unit)
    return "%d B" % b


# -------------------------------------------------------------------- main ---

CALL_COLUMNS = [
    "tool_use_id", "session_id", "project", "transcript", "cwd", "git_branch",
    "entrypoint", "cc_version", "model", "ts", "ts_ms", "date", "hour",
    "tool_name", "tool_category", "mcp_server", "mcp_tool",
    "is_sidechain", "from_subagent_file", "caller",
    "input_bytes", "output_bytes", "duration_ms", "result_ts",
    "bash_command", "bash_primary", "bash_bins", "bash_heredoc",
    "file_path", "file_ext", "url", "query", "subagent_type", "skill_name",
    "is_error", "error_kind", "error_group", "error_text",
]
URL_COLUMNS = ["source", "url", "domain", "title", "query", "project",
               "session_id", "ts", "date", "tool_use_id"]
TURN_COLUMNS = [
    "request_id", "session_id", "project", "transcript", "model", "ts", "date", "hour",
    "trigger_kind", "latency_ms", "ttfb_ms", "decode_ms", "output_tps",
    "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens",
    "cache_hit_ratio", "stop_reason", "service_tier", "speed",
    "is_sidechain", "entrypoint", "blocks", "tool_uses", "thinking", "idle",
]


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="cc-toolstat",
        description="Audit your Claude Code tool usage from local session transcripts.",
        epilog="Reads local files only. Nothing is uploaded.")
    ap.add_argument("--dir", help="Claude data dir (default: $CLAUDE_CONFIG_DIR or ~/.claude)")
    ap.add_argument("--out", default="cc-toolstat-out", help="output directory")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="only calls on or after this local date")
    ap.add_argument("--until", metavar="YYYY-MM-DD", help="only calls on or before this local date")
    ap.add_argument("--redact", action="store_true",
                    help="strip paths, commands, queries, URLs and project names")
    ap.add_argument("--no-html", action="store_true", help="skip the dashboard")
    ap.add_argument("--no-tables", action="store_true", help="skip parquet/CSV output")
    ap.add_argument("--csv", action="store_true", help="force CSV output even if pyarrow exists")
    ap.add_argument("--open", action="store_true", dest="open_",
                    help="open the dashboard when done")
    ap.add_argument("--jobs", type=int, default=min(16, (os.cpu_count() or 4)),
                    help="parser processes")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--version", action="version", version="cc-toolstat " + __version__)
    a = ap.parse_args(argv)

    say = (lambda *m: None) if a.quiet else (lambda *m: print(*m, file=sys.stderr))

    root, files = find_transcripts(a.dir)
    if not files:
        tried = ", ".join(data_dirs(a.dir))
        print("No Claude Code transcripts found. Looked in: %s\n"
              "Point --dir at the directory that contains 'projects'." % tried, file=sys.stderr)
        return 2
    say("Reading %s transcripts from %s" % (fmt_int(len(files)), root))

    calls, urls, turns = [], [], []
    payload = [(f, root) for f in files]

    def collect(results):
        for c, u, t in results:
            calls.extend(c)
            urls.extend(u)
            turns.extend(t)

    if a.jobs > 1 and len(files) > 4:
        try:
            with ProcessPoolExecutor(max_workers=a.jobs) as ex:
                collect(ex.map(parse_transcript, payload, chunksize=8))
        except Exception as e:                       # sandboxes without fork/sem support
            say("  parallel parse unavailable (%s); falling back to one process" % e)
            calls, urls, turns = [], [], []
            collect(parse_transcript(i) for i in payload)
    else:
        collect(parse_transcript(i) for i in payload)

    # A resumed or forked session replays earlier turns into a new transcript.
    # tool_use ids are unique per API call, so keep the first and drop the copies.
    calls.sort(key=lambda r: r["ts_ms"] or 0)
    seen, deduped, dupes = set(), [], 0
    for r in calls:
        k = r["tool_use_id"]
        if k and k in seen:
            dupes += 1
            continue
        if k:
            seen.add(k)
        deduped.append(r)
    calls = deduped
    keep_ids = seen
    urls = [u for u in urls if not u["tool_use_id"] or u["tool_use_id"] in keep_ids]
    useen, udd = set(), []
    for u in urls:
        k = (u["tool_use_id"], u["url"])
        if k in useen:
            continue
        useen.add(k)
        udd.append(u)
    urls = udd
    turns.sort(key=lambda t: t.get("ts") or "")
    tseen, tdd, tdupes = set(), [], 0
    for t in turns:
        k = t["request_id"]
        if k and k in tseen:
            tdupes += 1
            continue
        if k:
            tseen.add(k)
        tdd.append(t)
    turns = tdd
    say("  %s tool calls (%s replayed copies dropped) · %s url rows · %s model turns (%s dropped)"
        % (fmt_int(len(calls)), fmt_int(dupes), fmt_int(len(urls)),
           fmt_int(len(turns)), fmt_int(tdupes)))

    if a.since or a.until:
        for r in calls:
            r["date"], r["hour"] = local_parts(r["ts"])
        for u in urls:
            u["date"], _ = local_parts(u["ts"])
        for t in turns:
            t["date"], t["hour"] = local_parts(t["ts"])
        lo, hi = a.since or "0000-00-00", a.until or "9999-99-99"
        calls = [r for r in calls if r["date"] and lo <= r["date"] <= hi]
        urls = [u for u in urls if u["date"] and lo <= u["date"] <= hi]
        turns = [t for t in turns if t["date"] and lo <= t["date"] <= hi]
        say("  %s calls in %s..%s" % (fmt_int(len(calls)), lo, hi))

    if not calls:
        print("No tool calls matched.", file=sys.stderr)
        return 1

    git = Counter()
    for r in calls:
        if r["bash_command"] and "git" in r["bash_command"]:
            for m in GIT_SUB.finditer(r["bash_command"]):
                git[m.group(1)] += 1

    if a.redact:
        calls, urls, turns = redact_rows(calls, urls, turns)
        say("  redacted: paths, commands, queries, URLs and project names removed")

    os.makedirs(a.out, exist_ok=True)
    cube = build_cube(calls, urls, turns, git, redacted=a.redact)
    written = []

    if not a.no_tables:
        written.append(write_table(calls, os.path.join(a.out, "tool_calls"),
                                   CALL_COLUMNS, want_parquet=not a.csv))
        written.append(write_table(urls, os.path.join(a.out, "web_urls"),
                                   URL_COLUMNS, want_parquet=not a.csv))
        if turns:
            written.append(write_table(turns, os.path.join(a.out, "model_turns"),
                                       TURN_COLUMNS, want_parquet=not a.csv))

    report_path = os.path.join(a.out, "report.txt")
    text = write_report(calls, urls, turns, cube, git, report_path)
    written.append(report_path)

    dash = None
    if not a.no_html:
        dash = os.path.join(a.out, "dashboard.html")
        with open(dash, "w") as fh:
            fh.write(HTML_TEMPLATE.replace(
                "/*__CUBE__*/", json.dumps(cube, separators=(",", ":"), default=str)))
        written.append(dash)

    m = cube["meta"]
    if not a.quiet:
        head = text.split("=" * 78)[2] if text.count("=" * 78) > 2 else ""
        print(head.rstrip())
        print("\nWrote:")
        for p in written:
            print("  %-52s %s" % (p, _bytes(os.path.getsize(p))))
        if dash:
            print("\nOpen the dashboard:  file://%s" % os.path.abspath(dash))

    if a.open_ and dash:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(dash))
    return 0


if __name__ == "__main__":
    sys.exit(main())
