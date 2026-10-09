# jevguard

A prompt-injection guard for [Claude Code](https://code.claude.com). It scans what tools bring in
from outside (web pages, search results, MCP responses, output of commands that fetch from the
internet, files those commands saved) before the model reads it, and withholds results that
score as an injection.

Scoring is done by [Jev](https://docs.typesafe.ai/concepts/system-one), TypeSafe's decision
model: it answers fixed questions about a text with probabilities and generates nothing. The
extraction code, the two questions, the chunking and the thresholds come unchanged from
[jooray/hermes-firewall](https://github.com/jooray/hermes-firewall) (MIT), which built and
benchmarked this gate for Hermes Agent; see
[the write-up](https://juraj.bednar.io/en/blog-en/2026/09/28/a-prompt-injection-gate-for-my-ai-agent-what-worked-what-didnt-and-the-benchmark/).
This repository is the Claude Code side: hooks, origin tracking for Claude Code's tools, result
replacement in each tool's own shape, and a gate in front of risky actions.

It is one layer, not a security boundary. A detector misses some attacks and nobody has tested
this one against an attacker who adapts to it. Keep permissions tight.

## How it works

Two Claude Code [hooks](https://code.claude.com/docs/en/hooks) run `bin/jevguard-hook`:

**PostToolUse** (after a tool ran, before its result reaches the model)

1. *Origin.* The result is classified by where its content came from, not by the tool:
   `WebFetch`, `WebSearch` and MCP tools are outside content; so is `Bash` when the command
   names a public URL or is a tool that only talks to a remote service (`gh`, ...); so are
   files a fetching command saved (`curl -o`, `> file`) and anything under `external_paths`.
   Such a file stays outside content however it is read back: `Read`, `cat page.html`,
   `cd dir && head f`, a glob, a variable the command sets, a path inside `python -c "..."`,
   or a `Grep` over a parent directory whose result lists it. So does a copy of it: what a
   command that handles outside content writes (`cp`, `mv`, `> file`, `tee`, `-o file`) is
   tracked the same way.
   Everything else is local and, by default, is not scanned and never leaves the machine.
2. *Extract.* Plain code reveals what a human would not see: invisible Unicode tag characters,
   zero-width and bidi characters, hidden HTML, comments, attribute text, base64 blobs, image
   metadata. Hiding text is recorded as a flag of its own.
3. *Score.* The text goes to Jev in 12,000-character chunks with two questions: does it contain
   a command unrelated to the rest of the content, and is the passage ordinary content, a normal
   request, or an instruction aimed at an AI model. The highest probability over all chunks is
   the score.
4. *Decide.* Score ≥ 0.38: injection. Score ≥ 0.20, hidden text, or a part that could not be
   read (an image without OCR, undecodable data): flagged. The verdict is computed in code.
5. *Act.* In `log` mode nothing changes for the model. In `block` mode the whole result is
   replaced by a short notice (`updatedToolOutput`) and the original goes to a quarantine file.
   Nothing is ever added to a result that passes. The notice carries a seal made with a key
   kept on this machine; only sealed text is skipped when it turns up in a later result.
   Text that merely looks like a notice, or like any other harness message, is scored.
   The guard's own `log`, `status` and `scan` output is sealed the same way when it is not
   going to a terminal (each line ends in a `#jg:` tag): it talks about injections, and
   without the seal the guard blocked its own log on the first day it ran.

Every scan is one line in `~/.local/state/jevguard/scans.jsonl`: tool, origin, verdict, score,
size, timing, a hash. Never the content.

**PreToolUse** (before a tool runs)

Two checks that read the call itself, no model:

- *Changes to the guard.* A call that would change the guard's settings, state, release list
  or code, run `jevguard mode|gate|install|uninstall|release|show`, or touch a Claude Code
  `settings*.json` (the hooks live there) is held for your approval. That holds whether the
  file is named directly, by glob or brace expansion (`rm ~/.claude/settings*.json`),
  through a directory above it (`rm -rf ~/.claude`), or as the place a command writes to in
  any spelling (`curl -o/path`, `--output-dir` with `-O`, `cd` there and download,
  `cp -t`, `dd of=`), and for commands run from inside the guard's directories. Reading a
  settings file (`cat`, `jq`, `grep`) is not held; reading the guard's own directory is,
  because the API key is there. In every session, whatever `gate` says. Switch off with
  `protect_guard: false`.
- *Risky actions after outside content.* An HTTP request with a body, or one whose address
  or headers are filled in when it runs, `git push`, `ssh`/`scp`, sending mail, publishing,
  an MCP tool that sends or changes something, or touching `~/.ssh`, shell startup files and
  git hooks. If the session has read outside content, the call is logged, or, with `gate`
  set to `ask-flagged` / `ask-external`, held for approval. A session counts as flagged once
  a result scored as an injection or passed without a full scan, and also when its recorded
  state cannot be read.

If the guard itself fails before a call (an error, unreadable settings), the call is held for
approval rather than let through unchecked.

Both read what a command says in plain sight: programs and their options, `bash -c '...'`,
`find -exec`, `$(...)`, paths after `cd`. That is an approval step, not a wall; see the limits
below.

The check before a call takes about 35 ms on the machine this was developed on.

## Install

Needs Python 3.11+ on Linux or macOS and a TypeSafe API key. No packages to install.

```bash
git clone https://github.com/Dehumanizer77/jevguard ~/.local/share/jevguard
mkdir -p ~/.config/jevguard && chmod 700 ~/.config/jevguard
umask 077; cat > ~/.config/jevguard/typesafe.key      # paste the key, Enter, Ctrl-D

~/.local/share/jevguard/bin/jevguard selftest         # one benign and one attack sample through the API
~/.local/share/jevguard/bin/jevguard install          # adds the hooks to ~/.claude/settings.json (backup kept)
```

Install from a checkout nobody works in. The guard asks before any call that touches its own
code, so developing inside the installed copy means approving every edit.

It starts in `log` mode. Run it that way on your own traffic first and read what would have
been blocked; upstream's first week of blocking produced only false positives, most of them the
agent harness's own text.

```bash
jevguard status                 # settings, key, token use, counts from the log
jevguard log                    # recent scans that were not a plain pass
jevguard show fw-20261009-ab12cd      # read a quarantined result (your own terminal only)
jevguard release fw-20261009-ab12cd   # let exactly that content pass from now on
jevguard mode block             # start withholding; `jevguard mode log` to go back
jevguard gate ask-flagged       # ask before risky actions once something was flagged
jevguard uninstall
```

`show` and `release` are for you, reading what was blocked. They refuse to run without a
terminal or when started from inside Claude Code, and the hook asks you before any call that
runs them. Neither is a lock; see the limits below.

`install` also adds two `permissions.deny` rules, `Read(~/.config/jevguard/**)` and
`Read(~/.local/state/jevguard/**)`: the API key and the seal key are there, and no hook runs
before Claude Code's own file tools read a file. `uninstall` removes them.

## Settings

`~/.config/jevguard/config.json`; every key is optional. Defaults and their reasons are in
[`jevguard/config.py`](jevguard/config.py).

| Key | Default | |
|---|---|---|
| `mode` | `log` | `log` or `block` |
| `gate` | `log` | `off`, `log`, `ask-flagged`, `ask-external` |
| `scan_local` | `false` | also scan local files and local command output (they block at `local_block`, 0.6) |
| `scan_private_hosts` | `false` | treat fetches from localhost and private addresses as outside content |
| `external_paths` | `["~/Downloads"]` | directories whose files are outside content |
| `track_clones` | `false` | treat directories created by `git clone` as outside content |
| `skip_tools` | claude.ai Gmail, Drive, Calendar, Docs connectors | tool-name patterns never scanned |
| `on_error` | `open` | `closed` withholds outside content that could not be fully scanned: the API failed, the guard hit an error, or part of the result was unreadable (block mode). Without `tesseract` that includes every image from outside |
| `protect_guard` | `true` | ask before any call that would change the guard or the Claude Code settings that run it |
| `daily_token_budget` | 5,000,000 | scanning stops for the day beyond this |
| `model` | `jev-1.13.0` | pinned; the thresholds were fitted on this version |

Everything that is scanned is sent to TypeSafe. The defaults keep local files, private-network
fetches and the private connectors out of that; each switch above widens it.

## What it does not cover

- Files pulled in with `@file`, `CLAUDE.md`, memory and skill files, MCP tool descriptions and
  server instructions, text you paste yourself: Claude Code runs no tool-result hook for these.
- An outside file reached without being named: a script written earlier that opens it, or a
  recursive search that prints matches without file names. The guard follows such files by
  name. When a session has downloaded files, commands that pick their files at run time
  (`$(...)`, `xargs`, `find`) are scanned too. `scan_local` closes the rest, at the price of
  sending local content for scoring.
- A download whose resting place the command does not say: a name chosen by the server
  (`curl -J`), a destination held in a variable set elsewhere, an archive unpacked into the
  current directory, files a script fetches on its own.
- Text in the pixels of an image, unless `tesseract` is installed. Image metadata is read.
- Results shorter than three words, and reports returned by subagents (their own tool calls are
  scanned).
- Claude Code on the web and cloud sessions: they do not read this machine's settings.
- An attack the model does not recognise. Upstream measured 88.5% of attacks blocked and 3.5% of
  benign items blocked on its 718-item test set, through Venice with `jev-latest`; those numbers
  have not been re-measured through this code path.
- An agent that sets out to get around it. The agent runs as the same operating-system user
  as you. The checks before a call read the command as written, so a command that hides what
  it does (encoded, or put in a script first) is not recognised, and anything the agent can
  run can also edit the guard's files or fake a terminal. To make the guard's files a real
  boundary, take them away from that user: run Claude Code in its
  [sandbox](https://code.claude.com/docs/en/sandboxing) with `~/.config/jevguard`,
  `~/.local/state/jevguard`, the checkout and `~/.claude/settings.json` denied for writing, or
  make them root-owned so that changing them takes `sudo`.

## Tests

```bash
python3 -m pytest tests -q      # the real hook script against a stand-in scoring API
tests/e2e_claude.py             # a headless Claude Code session: does the model see only the notice?
```

Run `tests/e2e_claude.py` after a Claude Code update. A replacement whose shape no longer matches
a built-in tool's output is ignored by Claude Code without an error, and the model then reads the
original.

## License and credits

MIT, see [`LICENSE`](LICENSE).

`jevguard/core/` is copied unchanged from
[jooray/hermes-firewall](https://github.com/jooray/hermes-firewall) by Juraj Bednár, also MIT,
and keeps its own notice (`jevguard/core/LICENSE`, source commit in `jevguard/core/UPSTREAM`).
One part of it is not used: its removal of the Hermes and BrowserOS harness messages before
scoring is replaced by the sealed-notice check in `jevguard/firstparty.py`.
