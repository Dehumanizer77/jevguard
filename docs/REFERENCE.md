# jevguard reference

What jevguard is and how to install it is in the [README](../README.md).

## How it works

The agent's hooks run `bin/jevguard-hook` at two points. The names below (hooks, tools,
`updatedToolOutput`) are Claude Code's [own](https://code.claude.com/docs/en/hooks); for
another agent its adapter translates them.

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

   In Claude Code a shell command that exits with an error status does not come back this
   way at all. Claude Code starts another hook for it (`PostToolUseFailure`), and a hook
   there can add a remark for the model but replace nothing. So in `block` mode Claude Code
   is set to run its shell commands through `bin/jevguard-shell` (`CLAUDE_CODE_SHELL_PREFIX`).
   For a command whose output would be scanned, that program holds the output until the
   command has finished, has it scored whole, and prints it or the notice, with the
   command's own exit status. It covers what the hook cannot: a command that fails, one that
   is killed for running too long, and everything after the first 30,000 characters. A
   `Monitor`'s command comes through the same program and is let through as it comes: it is
   known by where Claude Code sends its output (a socket; a `Bash` command's goes to a file),
   not by anything a call can say about itself. Where it cannot be worked out whether a
   command's output comes from outside, the output is held and `on_error` decides. The
   hook on `PostToolUseFailure` is there for the errors of other tools (an MCP tool's error
   text): it scans and logs them and, when one scores as an injection, says so beside it
   (`not-withheld` in the log), since nothing can be put in its place.

   A command sent to the background returns nothing at once; what it prints reaches the model
   later and is still that command's output. In Claude Code it goes to a file the model is told
   to read: if the command is outside content, that file is tracked like a download, however
   it is read. In Grok and Hermes another tool hands the output over
   (`get_command_or_subagent_output`, `process`): its result is judged as the output of the
   command that printed it.

   A result too large to hand over is saved to a file by the agent, and the model is told to
   read that. In Claude Code the hook is then given only the first 30,000 characters of a
   shell command's output, and of an MCP result over about 100 KB nothing at all, just a
   message naming the file. The file is this call's output: it is tracked like a download
   when the call is outside content, and a withheld result no longer says where it is. That
   message is taken apart like the redirect notice below (scored whole, it is withheld every
   time). Grok's `output_file` is followed the same way; in Hermes everything under its
   spill-over cache counts as outside content.

   One message of a tool is taken apart instead: `WebFetch`'s notice that an address redirects
   to another host. It tells the model to fetch the new address and quotes the agent's own
   prompt, so scored whole it was withheld every time. The guard writes that notice out again
   from the address and the prompt of the call itself and the two parts the server supplied
   (the new address and the status line). Only if that comes out equal to the result are those
   two parts scored and nothing else, the address also with its `%` escapes decoded. A notice
   with a word added, another prompt or a second address is scored whole, as before.

Every scan is one line in `~/.local/state/jevguard/scans.jsonl`: tool, origin, verdict, score,
size, timing, a hash. The log never holds the content.

**PreToolUse** (before a tool runs)

Two checks read the call itself and use no model:

- *Changes to the guard.* A call that would change the guard's settings, state, release list
  or code, run `jevguard mode|gate|install|uninstall|quarantine|show|release|discard|trust|untrust|own|disown`, or touch a file
  that decides whether an agent runs the hooks is held for your approval. Those files are a
  Claude Code `settings*.json`, the hook files the guard installs into for the other agents,
  and each agent's own switches for hooks (`~/.grok/disabled-hooks` and Grok's `*.toml`,
  `~/.codex/config.toml`, `~/.copilot/config.json`, `~/.hermes/config.yaml`), in the home
  directory and in a project. That holds whether the
  file is named directly, by glob or brace expansion (`rm ~/.claude/settings*.json`),
  through a directory above it (`rm -rf ~/.claude`, `mv ~/.grok/hooks x`), or as the place a command writes to in
  any spelling (`curl -o/path`, `--output-dir` with `-O`, `cd` there and download,
  `cp -t`, `dd of=`), and for commands run from inside the guard's directories. What `ssh`
  runs on another host (its command, and a here-document or here-string it sends to a shell
  there) is read as commands run here, as the host may be this one or share the home, and
  starting where sshd starts them, in the home directory with `$PWD` set to it:
  `ssh host 'touch ~'` and `ssh host 'touch .'` are held as `touch ~` is. It is read as a
  shell of its own: what it leaves to run at its end (a trap) runs there too, and its `cd`
  does not move the commands after `ssh`. A shell there that reads its commands from a pipe
  (`echo ... | ssh host`) is held, as `echo ... | bash` is. The home directory and those above it named
  there do not by themselves make `ssh` a change (`ssh host 'du -sh ~'`), a file in the home
  still does (`ssh host 'cat ~/.claude/settings.json'`), and ssh's own options
  (`-o LocalCommand=`, `-E`) and redirections are read as running here. The home and those above it
  stop counting for `ssh` only where each of its words is one word as written (no variable,
  glob or brace that may vanish or split); otherwise its words count as they are as well. What it sends to a program other than a shell
  is data and counts as it is. Reading a
  settings file (`cat`, `jq`, `grep`) is not held; reading the guard's own directory is,
  because the API key is there. This applies in every session, whatever `gate` says. Switch
  off with `protect_guard: false`.

  The same goes for the file tools, by every file the call changes: a patch (Codex's
  `apply_patch`, Hermes' `patch`) is read for the files named in it, and one that cannot be
  read is held. A tool the guard has no model of, an MCP server's or one an agent added
  under a name its adapter does not know, is held when one of its arguments is the path of
  such a file.
- *Risky actions after outside content.* An HTTP request with a body, or one whose address
  or headers are filled in when it runs, `git push`, `ssh`/`scp`, sending mail, publishing,
  an MCP tool that sends or changes something, or touching `~/.ssh`, shell startup files and
  git hooks. If the session has read outside content, the call is logged, or, with `gate`
  set to `ask-flagged` / `ask-external`, held for approval. A session counts as flagged once
  a result scored as an injection or passed without a full scan, and also when its recorded
  state cannot be read.

When the guard holds a shell command for approval, it says why in the command itself, as
comment lines put on top of it:

```
# jevguard: CHANGES THE GUARD
# jevguard: why: the command runs `jevguard gate`
# jevguard: Claude says: Switch the gate off for this session
jevguard gate off
```

The same reason goes out with the question, and a terminal shows it. Other front ends do not:
the approval card of the mobile app shows the command, cut to one line, and nothing else. The
first line is short enough for that card. The third is what the agent itself said the call is
for, in its own words and unchecked. The lines are comments, the command under them runs as
it was written.

If the guard itself fails before a call (an error, unreadable settings), the call is held for
approval rather than let through unchecked.

Both read what a command says in plain sight: programs and their options, `bash -c '...'`,
`find -exec`, `$(...)`, paths after `cd`. That is an approval step, not a wall; see the limits
below.

The check before a call takes about 35 ms on the machine this was developed on. In `block`
mode in Claude Code, deciding whether a shell command's output is to be held adds about 45 ms
to each shell command; a hook's own command passes through the shell prefix in about one.

## Installation details

The steps are in the [README](../README.md#install). Step 4 there runs one `install` command
per agent, and this is what each one changes:

| Agent | What `install` changes |
|---|---|
| Claude Code | adds three hooks, two rules and, in `block` mode, a shell prefix to `~/.claude/settings.json`; backup beside it |
| Grok Build | writes `~/.grok/hooks/jevguard.json` |
| Codex CLI | adds its entries to `~/.codex/hooks.json`; backup `hooks.json.jevguard.bak` |
| Copilot CLI | writes `~/.copilot/hooks/jevguard.json` |
| Cursor | adds its entries to `~/.cursor/hooks.json`; backup `hooks.json.jevguard.bak` |
| Hermes | copies the plugin to `~/.hermes/plugins/jevguard` |

How far each row has been tried: the Claude Code row is the first installation. For Grok and
Codex the hook has been run against the live program (`tests/e2e_grok.py`, `tests/e2e_codex.py`)
from hook files those checks set up themselves; the file `install` writes for Grok is where
Grok's documentation says personal hooks go, and Codex's review step has not been gone through
by hand. The last three rows follow each agent's documentation and have not been run.

```
$ jevguard install
updated /home/you/.claude/settings.json (backup: settings.json.jevguard-20261009-221546.bak)

$ jevguard status
mode: log   gate: log   on_error: open   protect_guard: True   model: jev-1.13.0
hooks installed: yes (/home/you/.claude/settings.json)
shell commands run through the guard: no (log mode)
installed for other agents: grok, codex
API key: present (/home/you/.config/jevguard/typesafe.key)
...
```

For Claude Code, `install` changes the user's `~/.claude/settings.json`: it adds its hooks next to any that
are already there and two `permissions.deny` rules, `Read(~/.config/jevguard/**)` and
`Read(~/.local/state/jevguard/**)` (the API key and the seal key are in those directories, and
no hook runs before Claude Code's own file tools read a file; the rules were checked to hold
on the first installation). `jevguard --settings <file> install` writes to another settings
file.

In `block` mode it also sets `env.CLAUDE_CODE_SHELL_PREFIX` to `bin/jevguard-shell`. Claude
Code then runs every shell command through that program, and takes what it prints for the
command's output. The command you see and approve is not changed. Why it is needed, and
what it does, is under [How it works](#how-it-works).

- Every shell command, and every hook, now depends on that small file. It runs the line as
  it is whenever anything is not as expected, but if it should ever stand in the way, take
  the `CLAUDE_CODE_SHELL_PREFIX` line out of `~/.claude/settings.json` and start Claude Code
  again. Nothing else of the guard depends on it.
- The output of a command that reads from outside is held until the command has finished,
  so you do not see it come line by line. Local commands are run directly, as before.
- With Claude Code's own sandbox switched on, the prefix runs inside it, without the network
  and without a file of its own, and cannot scan. What that costs is `on_error`, as for any
  other failure of the guard: `open` passes the output on unscanned, `closed` withholds it.
  Allow `api.typesafe.ai` and writing to `~/.local/state/jevguard` in the sandbox settings
  to have it work there.

If you already use `CLAUDE_CODE_SHELL_PREFIX` yourself, `install` leaves yours and says so.

The other agents have no such rules. There the hook before a call does that work: when the
agent's own file tool is pointed at one of those two directories, or searches from a directory
above them, you are asked first (in Codex, Hermes and Cursor's file read, which cannot ask, the
call is refused).

A Claude Code session started afterwards uses the hooks. One that was already running started
using them at its next tool call when this was first installed; if step 5 of the installation
shows nothing for such a session, restart Claude Code. From then on, a call made inside Claude
Code that would change the guard (`jevguard mode`, an update, an edit to `settings.json`) asks
the owner for approval.

## Everyday use

```bash
jevguard --version              # the version, and the commit the clone is at
jevguard status                 # the same, then settings, key, token use, counts from the log
jevguard log                    # recent scans that were not a plain pass (--all for every scan)
jevguard quarantine             # every quarantined result, newest first, and how it begins (your own terminal only)
jevguard show fw-20261009-ab12cd      # read a quarantined result (your own terminal only)
jevguard release fw-20261009-ab12cd   # hand the original to Claude and let that content pass from now on
jevguard discard fw-20261009-ab12cd   # throw it away, and take back its release if it had one
jevguard discard --older-than 30d     # the same for everything quarantined more than 30 days ago (asks first)
jevguard trust https://docs.example.com/guide/   # never withhold what WebFetch gets from this address
jevguard own 'acme/*' solo/tool                  # your own GitHub repositories (`disown` takes them off)
jevguard mode block             # start withholding; `jevguard mode log` to go back
jevguard gate ask-flagged       # ask before risky actions once something was flagged
```

When a result is withheld, Claude says the source was blocked and names a quarantine id
(`fw-…`). If you think it was harmless, read it with `jevguard show <id>` and, if so, run
`jevguard release <id>`. `jevguard quarantine` lists them all with the tool, the score, what
the call was given and the first words of the text; `-n 20` shows only the newest twenty.
Control characters in what these commands print (an escape sequence, a carriage return, a
right-to-left override, a zero-width space) are written out as `\x1b`, `\r`, `\u202e`,
`\u200b`, so a result cannot work on your terminal or hide words from you. `release` does two
things:

- The original is written to `~/.local/state/jevguard-released/<id>.txt`. Tell Claude it is
  released; the notice it received names that file, and reading it with the Read tool is not
  scanned again. This is what makes a release work for a source that never comes back the same:
  a web page is summarised afresh on every fetch, an API answer carries a timestamp. Claude
  reads exactly the text you read: the guard keeps a record of every file `release` wrote and
  of its hash, and only a file that still matches that record is exempt. Anything else in that
  directory (a file put there some other way, a released original that was edited since) is
  scanned as outside content, and the hook asks you before a call that would write there.
- The content goes on the release list, so if a tool returns the very same content again it
  passes. An edited version is scanned as usual.

A result you do not release stays blocked: the guard scores what comes back every time, and
the quarantine is only a copy for you to read. It never empties itself. `jevguard discard <id>`
throws a copy away. If it had been released, the release is taken back first: its line comes
off the release list and the original written for Claude is deleted, so the same content is
blocked again. `jevguard discard --older-than 30d` does that for everything quarantined more
than 30 days ago (`12h`, `2w` and `90m` work too) and asks before it starts; `-y` skips the
question. Like `show` and `release` it runs only in your own terminal: an agent that could
empty the quarantine could hide from you what it had been shown.

`release` and `discard` both take several ids at once. They check every one before they act
on any: if one of them names no entry, nothing is released or discarded.

For an address that keeps being withheld without reason (documentation about hooks, articles
about prompt injection), there is a list of trusted addresses:

```bash
jevguard trust https://developers.openai.com/codex/     # a URL prefix: this path and below
jevguard untrust https://developers.openai.com/codex/
```

What `WebFetch` gets from a trusted address is scanned and logged as before (`would-block` in
the log when it scores as an injection) and is not withheld. Keep the prefixes narrow: whatever
such an address returns later, or redirects to, reaches Claude unread by anyone. The address
has to be plain: no percent escapes in the path (`%2e%2e` is `..` to the server), no `..`, `;`
or doubled slash, no braces or brackets. For MCP tools the equivalent is the `warn_tools`
setting.

The list does not reach `curl` or `wget`. With `WebFetch` the address is a field of the call;
what a shell command really fetches cannot be read off its text. An earlier version tried, and
was got around through a printed address, a header with a line break in it, a redirection from
`/dev/tcp`, `printf -v PATH`, a `?` the shell took for a glob, curl's own `%output` and a bare
`cd`. So a download in the shell is ordinary outside content: scanned, and withheld if it
scores as an injection. If that happens to a page you trust, fetch it with `WebFetch`, or
release the blocked result.

**No shell command is exempt from blocking because of what it looks like.** Two things are
still read off a command, and both only when the whole command is one program with its
arguments written out: no pipe, no second command, no redirection except `2>&1` or
`2>/dev/null` at the end, nothing for the shell to expand (a variable, `$(...)`, a glob, `~`,
a backslash), no line break.

`gh` about your own repositories. Everything `gh` prints counts as outside content, and short
status lines and the titles of your own commits score oddly: live, `OPEN MERGEABLE 2 false`
scored 0.38. List your own repositories with `jevguard own 'acme/*' solo/tool` (the `own_repos`
setting) and what one
`gh` command about them returns is withheld only from 0.6 up; between 0.38 and 0.6 it is logged
as flagged. This is a higher level, not an exemption: anyone can open an issue or write a
comment in a public repository, a clear injection scores near 1 either way, and the reply to
your own `gh pr create` or `gh api -X PATCH` is scored like everything else. The command has to
name the repository (`--repo owner/name`, `gh api repos/owner/name/...`, `gh repo view
owner/name`); it is not taken from the directory, because which repository `gh` picks there
depends on the remotes and settings of the checkout. So:

```bash
gh pr view 14 --repo acme/widget --json title,state      # your repository: the higher level
gh pr view 14 --repo acme/widget | head -20              # a pipe: ordinary outside content
git push && gh pr create --repo acme/widget --fill       # two programs: ordinary outside content
gh pr list                                               # no repository named: ordinary outside content
gh pr view 14 --comments --repo acme/widget              # may be the value of --comments: ordinary outside content
```

Use `--jq` or `--json` instead of a pipe, and run `git push` as a command of its own.

The last line is about where `--repo` stands. `gh` has hundreds of options and the guard does
not know which of them take a value, so `--label --repo=acme/widget` (a label, and no
repository named) cannot be told from a repository option by its looks. The option therefore
counts only where `gh` is certain to read an option whatever the others are: straight after
the subcommand, after an argument or a value (`gh pr view 14 --repo ...`,
`--json title --repo ...`) or after `--option=value`. Put it right after the subcommand and it
always counts: `gh pr view --repo acme/widget 14 --comments`. It also has to be the only
thing in the command that looks like one, and the command has to start `gh pr ...`,
`gh issue ...`, `gh run ...`, `gh workflow ...`, `gh release ...` or `gh label ...` with the
subcommand as the next word, or be `gh repo view owner/name` or `gh api`.

`gh pr list` and `gh issue list` are narrower still. Most of their options end up in one
GitHub search (`--search` as it is, `--author`, `--label`, `--assignee`, `--milestone` as terms
of it), and a search is addressed by what its query says, in GitHub's own syntax:
`repo:"stranger/widget"` in a query adds that repository to the results. The guard does not
read that syntax. For these two commands only the options that cannot put a word into a query
count, `--repo`, `--state`, `--limit`, `--json`, `--jq` and `--template`:

```bash
gh issue list --repo acme/widget --state open --json number,title --jq '.[].title'   # the higher level
gh issue list --repo acme/widget --label bug                                         # ordinary outside content
gh issue list --repo acme/widget --search 'is:open'                                  # ordinary outside content
```

Filter with `--jq` instead, which works on what came back. Any other command with `--search`
gets no higher level either.

Nor does a `gh api` call with an option the guard does not know, `--hostname` or `..` in its
path, a command with an address among its arguments, or any `gh` command while `GH_HOST` or
`GH_REPO` is set, gh's own settings send its requests through a socket (`http_unix_socket`), or
`PATH` has an empty or relative entry.

What the level says is where the command is addressed, not who wrote what comes back. An
issue, a comment, a pull request from a fork: your repository returns other people's text
too, and that is why this is a level and the result is still scanned.

A program you vouch for. `trusted_commands` takes program names (`"make"`); the output of such
a program is scanned and logged, never withheld. That is your word for the program, not
something the guard checks, and it holds for the same narrow form only: `make test`, not
`make test | head`, `./make test` or `cd elsewhere && make test`. There is no built-in list:
`git status`, `cp` or `date` look harmless and are not (`cp notes.txt /dev/stdout` prints a
file, `git switch main` prints the title of a commit someone else wrote).

`show` and `release` are for you, reading what was blocked. They refuse to run without a
terminal or when started from inside Claude Code, and the hook asks you before any call that
runs them. Neither is a lock; see the limits below.

Read the log with `jevguard log`, not by opening the files under `~/.local/state/jevguard`.
When its output goes to a program instead of a terminal, every line ends in a `#jg:` tag;
leave the lines whole (`grep`, `head` and `tail` are fine, `cut` is not), or the guard no
longer recognises them as its own.

## Other agents

The guard is an engine and one adapter per agent (`jevguard/agents/`). The engine decides; an
adapter knows how its agent calls a hook, what its tools are named, what shape their results
have, and how it is told to replace a result or to ask. How much of the guard works in an agent
depends on what that agent lets a hook do:

| Agent | Withholds a result | Before a risky call | Checked |
|---|---|---|---|
| Claude Code | every tool | asks you | live (`tests/e2e_claude.py`) |
| Grok Build | every tool | asks you | live against grok 1.0.30 (`tests/e2e_grok.py`) |
| Codex CLI | every tool | refuses the call | live against codex 0.160.0 (`tests/e2e_codex.py`) |
| Copilot CLI | every tool | asks you | from its documentation only |
| Cursor | MCP tools, file reads, shell output | asks you for shell and MCP, refuses for its other tools | from its documentation only |
| Hermes | every tool | refuses the call | from the notes of the plugin it is derived from |

How to put the guard into each of them is in the [README](../README.md#install), step 4. Settings, log,
quarantine and release are the same for all of them: one `jevguard status`, one `jevguard log`.

- **Grok** also runs the hooks in `~/.claude/settings.json`, so with the guard installed for
  Claude Code it is started by Grok too and recognises it. Installing for Grok as well gives it
  hooks without Claude Code's tool-name filter, which Grok's MCP tools do not fit.
  Grok can also search and fetch pages with tools that run on xAI's side ("backend tools",
  on by default). No hook on your machine is started for those, so the guard never sees what
  they return. `features.backend_tools = false` in `~/.grok/config.toml` turns them off, and
  Grok then fetches with its own `web_fetch`, which is scanned; `install --agent grok` says
  so and leaves the choice to you.
- **Codex** has no field for a replacement and no "ask". But when a hook after a call answers
  `decision: "block"`, Codex puts the hook's words in place of the tool's result, so the guard
  hands it the notice that way. The hook runs outside Codex's sandbox, so this holds whatever
  the sandbox allows the command. Where the guard would ask, the call is refused with the
  reason. Codex runs a hook only after you have reviewed it (`/hooks`).
- **Cursor** and **Copilot CLI** adapters are written from the documentation and have not been
  run against the programs. Cursor lets a hook replace only MCP results, so there a shell
  command whose output the guard would look at is rewritten to run through `bin/jevguard-run`,
  which scans what the command printed before Cursor gets it; that needs the command to be
  allowed the network. Nothing after that program can withhold the output, so a failure in it
  costs what `on_error` says, and that setting is written into the rewritten command for the
  case that the program cannot read the settings where it runs. Cursor asks only for shell
  and MCP calls; for its file tools the one event before the call can allow or deny, so what
  the guard would ask about is refused there. Cursor's own web tools cannot be covered.
- **Hermes** has no way to ask from a plugin; where the guard would ask, the call is refused.
- The output of a command run through `jevguard-run` is held until the command has finished.
- A result is read whole, whatever its fields are called. A field is passed over only when its
  value shows it is not content: a tag such as `"type": "text"`, a media type, or, in a
  built-in tool's result, something the call itself said (its command, its address).

## Settings

`~/.config/jevguard/config.json`; every key is optional. Defaults and their reasons are in
[`jevguard/config.py`](../jevguard/config.py).

| Key | Default | |
|---|---|---|
| `mode` | `log` | `log` or `block` |
| `gate` | `log` | `off`, `log`, `ask-flagged`, `ask-external` |
| `scan_local` | `false` | also scan local files and local command output (they block at `local_block`, 0.6); output of `gh` about your own repositories is then withheld from the lower of the two levels |
| `trusted_commands` | `[]` | program names whose output is scanned and logged, never withheld, e.g. `make`: your word for that program. Only when the whole command is that one program with its arguments written out |
| `scan_private_hosts` | `false` | treat fetches from localhost and private addresses as outside content. An address counts as private only when it plainly names such a host (`localhost`, `192.168.1.5`, `[::1]`, `nas.local`, a name without a dot; a port and a user part are fine). Anything a program might read another way is outside content: `localhost;other.example`, `134744072`, a backslash, a `#` straight after the host |
| `external_paths` | `["~/Downloads"]` | directories whose files are outside content |
| `track_clones` | `false` | treat directories created by `git clone` as outside content |
| `skip_tools` | claude.ai Gmail, Drive, Calendar, Docs connectors | tool-name patterns never scanned |
| `warn_tools` | `[]` | tool-name patterns that are scanned and logged, never withheld |
| `trusted_sources` | `[]` | URL prefixes; what `WebFetch` gets from them is scanned and logged, never withheld (`jevguard trust`). Not for `curl` or `wget` |
| `own_repos` | `[]` | your own GitHub repositories, as `owner/name` or `owner/*`; what one `gh` command naming such a repository returns is withheld only from `own_repos_block` up, and a `Monitor` running such a command is not asked about |
| `own_repos_block` | `0.6` | that level |
| `on_error` | `open` | `closed` withholds outside content that could not be fully scanned: the API failed, the guard hit an error, or part of the result was unreadable (block mode). Without `tesseract` that includes every image from outside |
| `protect_guard` | `true` | ask before any call that would change the guard or the agent settings that run it |
| `daily_token_budget` | 5,000,000 | scanning stops for the day beyond this |
| `model` | `jev-1.13.0` | pinned; the thresholds were fitted on this version |
| `url` | `https://api.typesafe.ai/v1/systemone` | where the text is sent for scoring |
| `key_file` | `~/.config/jevguard/typesafe.key` | the file holding the API key |

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
- What a `Monitor` prints (Claude Code, Grok), or is sent over a WebSocket it opens. Each
  line goes into the conversation as a notification, and no hook is called for those, so it
  can be neither scanned nor withheld.
  When the command reads from outside, the guard asks before the monitor starts (in `block`
  mode; in `log` mode it records it) and counts the session as flagged. If you approve, that
  output reaches the model unscanned. A monitor on one of your `own_repos` is recorded
  (`logged`) and not asked about: unscanned all the same. That holds for one `gh` command
  that names the repository and nothing else (`gh run watch --repo you/project 4242`); a
  loop or a pipe around it is asked about like any other.
- The error of a tool call that fails, other than a shell command in Claude Code. In
  Claude Code a failed call comes back through a hook that can add a remark and replace
  nothing (tried against 2.1.295 with every field there is). Shell commands are covered by
  the shell prefix, in `block` mode. What an MCP tool or `WebFetch` returns as an error is
  scanned and logged, and the model is told when it scores as an injection, but it has read
  it by then. The same goes for a shell command where the prefix is not in place: `log`
  mode, a prefix of your own, Claude Code's sandbox without the network, or a line of a
  shape a later version builds differently (`tests/e2e_claude.py` has a step that fails
  then). In Copilot CLI a failed call is not looked at at all (its reference says a hook can
  only add context there), and what Cursor does is not known. Codex and Grok report a failed
  command through the ordinary hook, where it is scanned and withheld like any other (both
  tried).
- The result of a built-in tool whose name the adapter does not know (MCP tools always are
  scanned; in Copilot CLI an unknown tool is too), and of any tool that does not run on your
  machine: Grok's backend tools, see [Other agents](#other-agents).
- A result too large to hand over, outside Claude Code, Grok and Hermes. Codex cuts it down
  to its beginning and end and gives the hook exactly what it gives the model, with no file
  (tried). Copilot CLI writes a result over 51,200 bytes to a file in the temp directory and
  hands the model a reference (read from its package, not run): that file is not followed.
  What Cursor does is not known.
- A command the agent leaves running, outside Claude Code, Grok and Hermes. Codex starts its
  hook once, when the command has finished, with all of its output (tried:
  `tests/e2e_codex.py read-only background`). In Copilot CLI the output is read with
  `read_bash`, which is scanned as a tool the adapter does not know; a notice of completion
  is not a tool result.
- A file tool the guard has no model of, when the path it changes is inside a longer text it
  is given rather than an argument of its own. The patches of Codex, Copilot CLI and Hermes
  are read; another tool's own patch format would not be.
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
tests/e2e_grok.py               # the same against Grok Build
tests/e2e_codex.py              # the same against Codex CLI (optionally: a sandbox mode)
```

The first needs pytest (`python3-pytest`) and, for one image test, Pillow; neither needs the
API key or the network. The others start the real agent (`claude -p`, `grok -p`, `codex exec`)
with temporary hooks and a stand-in scoring API, so each needs that agent logged in and costs a
few cents of usage, but no API key and no installation of the guard. The Codex one puts a
`~/.codex/hooks.json` in place while it runs and refuses to start if you have one.

They test the code in this checkout, not a guard you have installed: the Claude Code one
leaves your own settings out of its sessions, the Grok one switches off the hooks Grok would
take from `~/.claude` and `~/.cursor` and does not run beside a guard installed for Grok
itself. (Before that, with the guard installed for Claude Code, the installed copy's hooks
ran in the Claude Code check as well and could have carried a failing result.)

Run the one for your agent after that agent is updated. A replacement whose shape no longer
matches a built-in tool's output is ignored by Claude Code without an error, and the model then
reads the original.
