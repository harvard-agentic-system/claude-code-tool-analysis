# cc-toolstat

Audit your own Claude Code tool usage. Points at the session transcripts already on your
disk, and produces a queryable table, a text report, and a self-contained interactive
dashboard.

One file, Python standard library only. It reads local files and uploads nothing.

```bash
curl -sO https://raw.githubusercontent.com/harvard-agentic-system/claude-code-tool-analysis/main/cc_toolstat.py
python3 cc_toolstat.py --open
```

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
- Plus: hour-of-day rhythm, file types touched, git subcommand mix, per-project breakdown,
  main-thread versus subagent share, model and entrypoint mix.

## Output

| file | what |
|---|---|
| `tool_calls.parquet` | one row per tool call, 38 columns — the fact table |
| `web_urls.parquet` | one row per URL searched or fetched |
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
| `--dir PATH` | Claude data dir. Defaults to `$CLAUDE_CONFIG_DIR`, then `~/.claude`, then `~/.config/claude` |
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

## Caveats

- `duration_ms` is request → result wall clock. For `AskUserQuestion` that measures how long
  you were away, not tool latency; it's excluded from the aggregate mean.
- Bash command shares sum past 100% because one call usually runs several commands.
- Git subcommands are counted by regex across the whole corpus and don't respond to the
  dashboard filters.
- Dates and hours use your machine's local timezone; transcript timestamps are UTC.

## Development

`template.html` is the dashboard source; `cc_toolstat.py` embeds a copy so the tool stays a
single file.

```bash
python3 build.py           # re-embed after editing template.html
python3 build.py --check   # fail if the embedded copy has drifted
```

MIT licensed.
