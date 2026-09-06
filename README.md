# cc-toolstat

Audit your own coding-agent tool usage. Points at the session transcripts already on your
disk — **Claude Code, Codex and Grok** — and produces a queryable table, a text report, and
a self-contained interactive dashboard.

One file, Python standard library only. It reads local files and uploads nothing.

```bash
curl -sO https://raw.githubusercontent.com/harvard-agentic-system/claude-code-tool-analysis/main/cc_toolstat.py
python3 cc_toolstat.py --list-agents   # what it can see on this machine
python3 cc_toolstat.py --open          # analyse everything it found
```

| agent | read from | notes |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` | richest source; everything below is available |
| Codex | `~/.codex/sessions/**/rollout-*.jsonl` | tool durations are dispatch-only (see below) |
| Grok | `~/.grok/sessions/**/updates.jsonl` | tool timestamps are whole seconds |

Every row in every table carries an `agent` column, and the dashboard gets an agent filter,
so you can compare corpora or isolate one.

## What it answers

- **Which tools do I actually use**, and how does that split by category — shell, file
  read, file write, web, subagent dispatch?
- **What fails, and whose fault is it?** The headline number most people get wrong: a raw
  error rate counts your own hooks and permission rules denying a call. cc-toolstat
  separates *blocked by policy* and *hook infrastructure* from genuine tool and command
  failures, so you get both numbers.
- **What am I really running inside Bash?** Heredoc bodies and quoted strings are stripped
  before tokenising, so an embedded Python script isn't counted as 40 shell commands.
- **Where do my web calls go** — which domains searches surface versus which pages actually
  get fetched.
- **How long does everything take?** Two clocks, measured separately: *tool latency* (call
  issued → result landed) and *model turn latency* (triggering result → last block of the
  reply). Percentiles, not means, plus end-to-end output tokens/sec, cache hit ratio, and
  where your machine time actually goes.
- **How hard is the model thinking?** Extended-thinking tokens per turn, how often thinking
  fires, what it costs in latency, and the prompt-cache TTL mix.
- **What follows what?** A tool-to-tool transition matrix, and whether a failed call recovers
  on the next one.
- **How much code moved?** Lines added and removed per edit, by file type.
- **Your own habits**: how many messages you queue while Claude works and how many you pull
  back, and how long your typed prompts actually run.
- Plus: hour-of-day rhythm, file types touched, git subcommand mix, per-project breakdown,
  main-thread versus subagent share, model and entrypoint mix.

## Output

| file | what |
|---|---|
| `tool_calls.parquet` | one row per tool call, 38 columns — the fact table |
| `web_urls.parquet` | one row per URL searched or fetched |
| `model_turns.parquet` | one row per inference: latency, tokens, thinking, cache TTL, stop reason |
| `dashboard.html` | self-contained interactive dashboard, filterable by project and date |
| `report.txt` | the same analysis as plain text |

Parquet needs `pyarrow`. Without it the tool writes `.csv.gz` instead and everything else
works the same.

## Usage

```bash
python3 cc_toolstat.py                      # analyse ~/.claude -> ./cc-toolstat-out
python3 cc_toolstat.py --open               # ...and open the dashboard
python3 cc_toolstat.py --since 2026-08-01   # only calls on or after a local date
python3 cc_toolstat.py --redact             # safe to share: see below
python3 cc_toolstat.py --dir ~/other/.claude --out ~/audit
```

| flag | effect |
|---|---|
| `--agent NAME` | limit to one agent (`claude`, `codex`, `grok`); repeatable |
| `--list-agents` | show which agents have transcripts here, then exit |
| `--dir PATH` | data dir for the selected agent, overriding its default location |
| `--out DIR` | output directory (default `cc-toolstat-out`) |
| `--since` / `--until` | filter by local date, `YYYY-MM-DD` |
| `--redact` | strip paths, commands, queries, URLs and project names |
| `--csv` | force CSV output even when pyarrow is available |
| `--no-html` / `--no-tables` | skip the dashboard / skip the tables |
| `--jobs N` | parser processes (default: min(16, cpu count)) |

### Sharing your results

The default output is **not** safe to share. `tool_calls.parquet` contains your shell
commands, file paths, search queries and error text; `dashboard.html` embeds your project
names, search queries and fetched URLs.

`--redact` replaces project names with salted hashes and drops `cwd`, `bash_command`,
`file_path`, `url`, `query` and `error_text` entirely. File *extensions*, tool names,
timings, counts and error classifications survive, so the shape of the analysis is intact.
Domains become `(redacted)`. The salt is random per run, so hashes do not correlate across
runs.

`examples/dashboard-redacted.html` in this repo was produced that way.

## How it reads the transcripts

Claude Code appends one JSON object per line to `~/.claude/projects/<encoded-cwd>/<session>.jsonl`,
with subagent transcripts under `<session>/subagents/`. A tool call is an assistant message
containing a `tool_use` content block; its outcome is the matching `tool_result` block in
the next user message, carrying `is_error`.

Three things that are easy to get wrong, and how this handles them:

1. **Replayed calls.** Resuming or forking a session copies earlier turns into a new
   transcript. `tool_use` ids are unique per API call, so rows are deduplicated on
   `tool_use_id`, keeping the earliest. On a real corpus this removed 201 of 45,149 rows.
2. **Heredocs.** `python3 - <<'PY' … PY` inside a Bash call would otherwise contribute
   `print`, `import`, `def` and every local variable to the "shell commands" histogram.
   Heredoc bodies and quoted strings are removed before tokenising — on one corpus this cut
   the apparent distinct-binary count from 18,932 to 542.
3. **`cd` prefixes.** 35% of Bash calls open with `cd <dir>`, so the first token is a poor
   proxy for what ran. `bash_bins` lists every distinct command in the call; `bash_primary`
   is the first real one.

Error text is matched against an ordered rule list into ~22 kinds, grouped into
`blocked_by_policy`, `hook_infra`, `command_failed`, `agent_mistake` and `infra_limit`.
On the corpus this was developed against, 99.9% of error text classified.

## Latency, and why the numbers are what they are

Two clocks, and they are not the same thing.

**Tool latency** is `tool_use` emitted → `tool_result` recorded. It contains the work
itself *and*, when a call needed your approval, however long you took to grant it. That is
why the report leads with percentiles: a single 19-hour `AskUserQuestion` moves a mean and
does nothing to a p50.

**Model turn latency** is the triggering `tool_result` → the last content block of the
reply: queue, prefill and decode together. Getting this right needs two corrections that
are easy to miss:

- One API call is written to the transcript as *several lines*, one per content block
  (thinking, text, then each `tool_use`), all repeating the same `usage` totals. Treating
  each line as an inference triple-counts turns and badly understates latency. Turns are
  grouped by `requestId`.
- Turns you started by typing are excluded — that gap contains your thinking time, not the
  model's. Only machine-triggered turns count.
- A machine-triggered turn that appears to take hours means the session was paused,
  interrupted or resumed with the wall clock still running. Anything over 10 minutes is
  flagged `idle` and kept out of the statistics; the count is reported. On the development
  corpus this was 226 of 38,498 turns, and removing them moved end-to-end throughput for
  one model from 6.6 to 25.5 output tokens/sec.

`out tok/s` is end-to-end, so it includes queue and prefill. A model used for many small
turns reads slower than one used for long ones — the report prints median output tokens per
turn beside it so the comparison is interpretable.

The dashboard recomputes percentiles under your filters from a log-bucketed histogram
(~1.6× steps), so its figures interpolate within a bucket and land within a few percent of
the exact ones. `report.txt` computes exact percentiles from the raw rows.

## Model internals, workflow shape, churn

Four more seams, each with its own footnote:

**Extended thinking.** `output_tokens_details.thinking_tokens` is per request, not per
transcript line — and on about 3% of requests it is absent from the first line and present
on a later one. Reading only the first line loses those: on the development corpus that was
the difference between 5,965 and 13,815 turns with thinking recorded. Turns take the maximum
seen across the request's lines.

**Transitions and recovery.** Tool-to-tool transitions come from ordering calls within a
session. On the development corpus 70% of transitions repeat the same tool — work arrives in
runs, not alternation — and 85% of failed calls recover on the very next one.

**Code churn** comes from `structuredPatch` on edit results, counting `+` and `-` lines.
Only an edit against an existing file carries a patch, so this covers about 20% of file
writes; creating a new file produces nothing to count. The panel states its own coverage.

**Your typed prompts** are measured from message bodies, not the `last-prompt` records —
those are truncated at exactly 201 characters and are useless for length statistics. Turns
the harness injects in the user role (`<task-notification>`, monitor events, system
reminders) are excluded; on the development corpus that removed 268 of 2,964 apparent
prompts.

## Comparing across agents

Two clocks differ per agent, and the tool refuses to blend them silently.

**Tool duration.** Every call carries a `duration_basis`, and only wall-clock bases enter
the latency statistics. Codex runs every command through a persistent shell, so the
duration it records is dispatch, not runtime — 91% of its command executions record under
1 ms. Those rows stay in the parquet, marked `dispatch_only`, and are excluded from
percentiles. Grok's timestamps are whole seconds, so its tool latency is marked
`wall_clock_1s` and quantises to 1 s.

**Turn latency.** Claude's is trigger → last block, so it contains queue, prefill and
decode. Codex's is generation-item time only, with no queue or prefill. Grok reports its own
`apiDurationMs`. The report prints a `latency_basis` table and says plainly not to compare
the p50 column across agents without reading it.

Everything counted by category rather than tool name — shell work, file reads, web calls —
compares cleanly, because Claude's `Bash`, Codex's `exec` and Grok's `run_terminal_command`
all land in the `shell` category.

## Adding another agent

A reader is a function `parse(path, root) -> (calls, urls, turns, events)` plus one entry in
`AGENTS` giving its label, base directories and glob. Emit rows with the same keys the
existing readers use, set `agent` and `duration_basis`, and everything downstream — dedupe,
report, cube, dashboard — works unchanged.

## Caveats

- `duration_ms` is request → result wall clock. For `AskUserQuestion` that measures how long
  you were away, not tool latency; it's excluded from the aggregate mean.
- Bash command shares sum past 100% because one call usually runs several commands.
- Git subcommands are counted by regex across the whole corpus and don't respond to the
  dashboard filters.
- Dates and hours use your machine's local timezone; transcript timestamps are UTC.
- Tool latency includes permission-prompt waits and cannot be separated from them; read the
  percentiles, not the mean.
- The "where the machine time goes" split excludes human-facing tools and any single wait
  over the idle cutoff, so it measures machine time rather than elapsed session time.

## Development

`template.html` is the dashboard source; `cc_toolstat.py` embeds a copy so the tool stays a
single file.

```bash
python3 build.py           # re-embed after editing template.html
python3 build.py --check   # fail if the embedded copy has drifted
```

MIT licensed.
