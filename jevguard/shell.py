"""Just enough shell reading to see which programs a command runs and which files it names.

This is pattern reading, not a shell. It follows what a command says in plain sight: programs,
their arguments, `cd`, variables assigned in the same command, `bash -c '...'`, `find -exec`,
command substitutions, redirections, globs. It cannot follow a script that opens a file, an
alias, or a value computed at run time; `Command.dynamic` says when part of the command is of
that kind.
"""

from __future__ import annotations

import fnmatch
import itertools
import math
import os
import re
import shlex

_SEPARATORS = set("();|&")
_REDIRECT_CHARS = set("<>&|")
# Programs that only run another program: the command after them is what counts. For each, the
# options whose value is a separate word, so that the value is not taken for the program.
_WRAPPERS = {"rtk": "", "sudo": "ughpCDRTU", "doas": "uC", "env": "uCS", "time": "fo", "nohup": "", "command": "",
             "builtin": "", "exec": "a", "nice": "n", "ionice": "cnp", "stdbuf": "ioe", "setsid": "",
             "timeout": "sk", "xargs": "IEnPLdsa", "watch": "n", "busybox": "", "toybox": "", "chronic": "",
             "unbuffer": "", "caffeinate": ""}
_WRAPPER_CHDIR = {("env", "C"), ("sudo", "D"), ("doas", "C")}
# Programs that take a command line as the string after -c (bash -lc '...', script -qc '...').
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_TAKES_COMMAND = _SHELLS | {"su", "script"}
_ASSIGN = re.compile(r"([A-Za-z_]\w*)=(.*)", re.S)
# \0 is a $ in single quotes (_LITERAL): a value known for it is put in all the same, wider than the truth
_VAR = re.compile(r"[$\0](?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
_SINGLE_QUOTED = re.compile(r"'[^']*'")
# Which files these read is decided when they run: substitution, xargs, find, eval, sourced files.
_DYNAMIC = re.compile(r"\$\(|`|<\(|(?:^|[\s;|&(])(?:xargs|eval|source|find)\s|(?:^|[;|&(])\s*\.\s+\S")
# A file path inside a longer string (code passed to python -c, a quoted script).
_EMBEDDED = re.compile(r"(?<![\w./~-])(?:~|\.{1,2})?(?:/[\w.+@%-]+)+|(?<![\w./~-])[\w.+@%-]+(?:/[\w.+@%-]+)+")
_GLOB = re.compile(r"[*?\[]")


def canonical(path: str, base: str = "") -> str:
    """Absolute path with ~, relative parts and symbolic links resolved."""
    path = os.path.expanduser(path.replace("\0", "").strip())
    if base and not os.path.isabs(path):
        path = os.path.join(base, path)
    return os.path.realpath(path)


def under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def tokens(cmd: str) -> list[str]:
    lex = shlex.shlex(cmd.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""  # '#' is part of many URLs
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: split without honouring them
        return re.findall(r"[();|&<>]+|[^\s();|&<>]+", cmd)


_BARE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")
_STDERR_ONLY = (" 2>&1", " 2>/dev/null")


def literal_command(cmd: str) -> list[str] | None:
    """The words of a command line that is one program with its arguments written out, or None.

    This is the only reading of a command that anything lenient may rest on, and it is narrow on
    purpose. The shell does much before it runs a line (it expands variables, globs and braces,
    it honours operators, redirections and assignments, and bash and zsh do not agree on all of
    it), and a reader that follows some of that is wrong about the rest. So nothing is followed.
    A line is accepted only when there is nothing to follow:

    - outside quotes, only letters, digits and _ @ % + = : , . / - . No ? * [ ] { } ~ # ! $ and
      no backslash: a `?` in an address is a glob to the shell;
    - in single quotes, anything; in double quotes, anything but $ ` and backslash;
    - no operator and no redirection at all: no ; | & ( ) < >. The one exception is a line that
      ends in `2>&1` or `2>/dev/null`, which moves or drops the program's own error output;
    - no control character, line breaks included.

    One program, then, and exactly these arguments. Which program a bare name runs is for the
    caller to worry about."""
    cmd = cmd.strip()
    for ending in _STDERR_ONLY:
        if cmd.endswith(ending):
            cmd = cmd[:-len(ending)].rstrip()
            break
    if any(ord(c) < 32 or ord(c) == 127 for c in cmd):
        return None
    words, word, i = [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if ch == " ":
            if word is not None:
                words.append("".join(word))
            word = None
        elif ch in "'\"":
            close = cmd.find(ch, i + 1)
            if close < 0 or (ch == '"' and any(c in "$`\\" for c in cmd[i + 1:close])):
                return None
            word, i = (word or []) + [cmd[i + 1:close]], close
        elif ch in _BARE and not (ch == "=" and word is None):  # zsh expands a leading = to a path
            word = (word or []) + [ch]
        else:
            return None
        i += 1
    if word is not None:
        words.append("".join(word))
    return words or None


class Command:
    def __init__(self, cwd: str = ""):
        self.programs: list[list[str]] = []  # argv of each simple command, wrappers removed
        self.program_dirs: list[list[str]] = []  # for each program, the directories it may be running in
        self.program_paths: list[set[str]] = []  # for each program, the paths its arguments name
        self.program_globs: list[list[str]] = []  # and the glob patterns
        self.program_fed: list[bool] = []    # its arguments come from elsewhere: xargs, $(...), a variable
        self.writes: set[str] = set()        # canonical targets of > >> &> redirections
        self.dirs: list[str] = [canonical(cwd)] if cwd else []  # the starting directory and every `cd` target
        self.paths: set[str] = set()         # canonical paths the command names
        self.globs: list[str] = []           # absolute glob patterns it names
        self.dynamic = False                 # part of it is only known at run time

    def names(self, root: str) -> bool:
        """The command runs in root, names something inside it, or uses a glob that can match it."""
        if any(under(d, root) for d in self.dirs) or any(under(p, root) for p in self.paths):
            return True
        return any(glob_reaches(g, root) for g in self.globs)


_BRACES = re.compile(r"\{([^{}]*)\}")


def expand_braces(token: str, limit: int = 64) -> list[str]:
    """`a/{b,c}.txt` as the shell expands it. A range ({1..9}) or an expansion past the limit
    becomes a `*`, which is read as a glob: wider than the truth, never narrower."""
    out = [token]
    for _ in range(8):  # nesting depth
        step = []
        for t in out:
            m = _BRACES.search(t)
            if not m or ("," not in m.group(1) and ".." not in m.group(1)):
                step.append(t)
                continue
            parts = m.group(1).split(",") if "," in m.group(1) else ["*"]
            step.extend(t[:m.start()] + part + t[m.end():] for part in parts)
        if step == out:
            break
        out = step
        if len(out) > limit:
            return [_BRACES.sub("*", token)]
    return out


def glob_reaches(pattern: str, path: str) -> bool:
    """The pattern can match the path or something inside it. A pattern that stops above the
    path (`ls /home/*` against a file three levels down) does not count."""
    pat, segs = pattern.split("/"), path.split("/")
    return len(pat) >= len(segs) and all(fnmatch.fnmatchcase(seg, p) for p, seg in zip(pat, segs))


def glob_reaches_above(pattern: str, path: str) -> bool:
    """The pattern can match a directory the path lies in (`rm -rf ~/.c*` against ~/.claude/x)."""
    pat, segs = pattern.split("/"), path.split("/")
    return len(pat) < len(segs) and all(fnmatch.fnmatchcase(seg, p) for p, seg in zip(pat, segs))


_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_]\w*)\1([^\n]*)\n(.*?)\n[ \t]*\2[ \t]*(?=\n|$)", re.S)
def _inline_heredocs(cmd: str) -> str:
    """`python3 - <<'EOF' ... EOF` as `python3 - '...'`. A here-document is text handed to the
    program, not shell: read line by line as commands, its first word of each line would be
    taken for a program and the paths it names would be lost. With an unquoted marker the shell
    still runs the $(...) and `...` inside it, so those follow the text as words of their own,
    where _read reads them as it reads any other."""
    def inline(m: re.Match) -> str:
        body, rest = m.group(4), m.group(3)
        runs = "" if m.group(1) else "".join(f" {run}" for run in _substitutions_in(body))
        return f" {shlex.quote(body)}{runs} {rest}"
    return _HEREDOC.sub(inline, cmd)


# A $ the shell takes as it is, in single quotes ('$1' in awk, $8924 in a quoted here-document).
# It stands in the words until a program's arguments are known, and is then a $ again.
_LITERAL = "\0"
# Marks where the output of a command substitution goes: $\x01<n>\x01 for the nth of a command.
_MARK = "\x01"
_RUN = re.compile(_MARK + r"(\d+)" + _MARK)
_WORD_BREAKS = set(" \t\n;&|()<>")
_OPERATORS = (";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|")
# Words after which the next one is again in the place of a command.
_BEFORE_COMMAND = {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "time"}


def _substitutions_in(text: str) -> list[str]:
    """The $(...) and `...` in the text of a here-document whose marker is not quoted, as written."""
    found, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text.startswith("$(", i) or text[i] == "`":
            end = _substitution_end(text, i + 2) if text[i] == "$" else _escaped_end(text, i + 1, "`")
            if end < 0:
                raise ValueError("a command substitution that does not end")
            found.append(text[i:end + 1])
            i = end
        i += 1
    return found


def _escaped_end(cmd: str, i: int, close: str) -> int:
    """Where the backtick that ends `...`, or the quote that ends $'...', is: only a backslash
    escapes it."""
    while i < len(cmd):
        if cmd[i] == "\\":
            i += 1
        elif cmd[i] == close:
            return i
        i += 1
    return -1


def _double_quote_end(cmd: str, i: int) -> int:
    while i < len(cmd):
        if cmd[i] == "\\":
            i += 1
        elif cmd[i] == '"':
            return i
        elif cmd.startswith("$(", i):
            i = _substitution_end(cmd, i + 2)
        elif cmd[i] == "`":
            i = _escaped_end(cmd, i + 1, "`")
        if i < 0:
            return -1
        i += 1
    return -1


def _brace_end(cmd: str, i: int) -> int:
    """Where the `}` that closes a `${` is: `${x:-)}` holds a `)` that closes nothing."""
    while i < len(cmd):
        ch = cmd[i]
        if ch == "\\":
            i += 1
        elif ch == "'":
            i = cmd.find("'", i + 1)
        elif ch == '"':
            i = _double_quote_end(cmd, i + 1)
        elif ch == "`":
            i = _escaped_end(cmd, i + 1, "`")
        elif cmd.startswith("$(", i):
            i = _substitution_end(cmd, i + 2)
        elif cmd.startswith("${", i):
            i = _brace_end(cmd, i + 2)
        elif ch == "}":
            return i
        if i < 0:
            return -1
        i += 1
    return -1


def _word_end(cmd: str, i: int) -> int:
    """Where the word that starts at i ends, the quotes and substitutions in it taken whole."""
    while i < len(cmd) and cmd[i] not in _WORD_BREAKS:
        ch = cmd[i]
        if ch == "\\":
            i += 1
        elif ch == "'":
            i = cmd.find("'", i + 1)
        elif ch == '"':
            i = _double_quote_end(cmd, i + 1)
        elif ch == "`":
            i = _escaped_end(cmd, i + 1, "`")
        elif cmd.startswith("$'", i):
            i = _escaped_end(cmd, i + 2, "'")
        elif cmd.startswith("$(", i):
            i = _substitution_end(cmd, i + 2)
        elif cmd.startswith("${", i):
            i = _brace_end(cmd, i + 2)
        if i < 0:
            return -1
        i += 1
    return i


def _arithmetic_end(cmd: str, i: int) -> int:
    """Where the second `)` of the `))` that closes a `$((` is, or -1. The shell takes `$((` for
    arithmetic when a `))` closes it, and otherwise for a `$(` with a subshell in it:
    `$((cd d; ls) )`."""
    depth = 0
    while i < len(cmd):
        ch = cmd[i]
        if ch == "\\":
            i += 1
        elif ch == "'":
            i = cmd.find("'", i + 1)
        elif ch == '"':
            i = _double_quote_end(cmd, i + 1)
        elif ch == "`":
            i = _escaped_end(cmd, i + 1, "`")
        elif cmd.startswith("$(", i):
            i = _substitution_end(cmd, i + 2)
        elif cmd.startswith("${", i):
            i = _brace_end(cmd, i + 2)
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if not depth:
                return i + 1 if cmd.startswith("))", i) else -1
            depth -= 1
        if i < 0:
            return -1
        i += 1
    return -1


def _substitution_end(cmd: str, i: int) -> int:
    """Where the `)` that closes a `$(` is, or -1. Inside it the shell reads commands afresh, and
    so does this, word by word: a `"` there opens a string of its own, a `#` that begins a word
    begins a comment to the end of the line, and in `case x in a) ...;; esac` the `)` ends a
    pattern (#52). A `)` closes the `$(` only when nothing opened in it is still open; one that
    fits nothing here, and a here-document (those are inlined before), give -1: the caller does
    not guess where the command ends."""
    if cmd.startswith("(", i):  # `$((`: arithmetic, where `<<` is a shift, when `))` closes it
        end = _arithmetic_end(cmd, i + 1)
        if end >= 0:
            return end
    open_: list[str] = []  # "(", "case" before its `in`, "pattern" and "arm" after it
    command = True  # the next word is the first of a command, where `case` and `esac` are the shell's
    while i < len(cmd):
        ch = cmd[i]
        if ch in " \t":
            i += 1
        elif cmd.startswith("\\\n", i):  # the line goes on: what follows starts a word as here
            i += 2
        elif ch == "\n":
            command, i = True, i + 1
        elif ch == "#":
            end = cmd.find("\n", i)
            i = len(cmd) if end < 0 else end
        elif ch in ";&|":
            op = next(o for o in _OPERATORS if cmd.startswith(o, i))
            if op in (";;", ";&", ";;&") and open_ and open_[-1] == "arm":
                open_[-1] = "pattern"
            command, i = True, i + len(op)
        elif ch in "<>":
            if cmd.startswith("<<", i) and not cmd.startswith("<<<", i):
                return -1
            i += 1
            while i < len(cmd) and cmd[i] in "<>&|" and cmd[i - 1] in "<>":
                i += 1
        elif ch == "(":
            if not (open_ and open_[-1] == "pattern"):  # `(a)`: a pattern may open with one
                open_.append("(")
            command, i = True, i + 1
        elif ch == ")":
            if not open_:
                return i
            if open_[-1] == "(":
                open_.pop()
            elif open_[-1] == "pattern":
                open_[-1] = "arm"
            else:
                return -1
            command, i = True, i + 1
        else:
            start, i = i, _word_end(cmd, i)
            if i < 0:
                return -1
            word, state = cmd[start:i], open_[-1] if open_ else ""
            if state == "case":
                if word == "in":
                    open_[-1] = "pattern"
            elif state == "pattern" and word == "esac":
                open_.pop()
            elif state == "pattern":
                pass  # a pattern, or one of several between `|`
            elif command and word == "case":
                open_.append("case")
            elif command and word == "esac" and state == "arm":
                open_.pop()
            command = command and word in _BEFORE_COMMAND
    return -1


def _lift_substitutions(cmd: str) -> tuple[str, list[str]]:
    """The command with each $(...) and `...` in it replaced by a `$` and a mark, and the commands
    they run. The tokenizer knows neither backticks nor the fresh quoting inside a `$(` in double
    quotes: in `echo "n: $(grep -c "a|b" f)"` it would pair the inner quotes with the outer ones,
    take the `|` for a pipe and `b" f)"` for a program, and not see the command at all. _read
    reads each where its mark is, before the command it is part of and with what was set up to
    there (#51). The `$` stays: that command has an argument from elsewhere.

    On the way, a `$` in single quotes becomes _LITERAL, $'...' becomes the '...' it stands for,
    and the quotes in a comment are taken out: the `'` in `# don't` would pair with the next one.
    So are its operators and brackets: the `)` in `# a)` would close a subshell for _read, and
    the `p=x` in `# a; p=x` would be an assignment. A substitution that does not end raises
    ValueError: what it runs cannot be told."""
    out, runs, i, quoted = [], [], 0, False
    word_start = True  # a word begins at i: `#` begins a comment there, not after `\ ` or in `a#`
    while i < len(cmd):
        ch = cmd[i]
        if ch == "\\":
            out.append(cmd[i:i + 2])
            word_start = word_start and cmd[i + 1:i + 2] == "\n"  # a joined line goes on as before
            i += 2
            continue
        if not quoted and ch == "'":
            end = cmd.find("'", i + 1)
            if end < 0:
                break
            out.append(cmd[i:end + 1].replace("$", _LITERAL))
            word_start, i = False, end + 1
            continue
        if not quoted and cmd.startswith("$'", i):
            end = _escaped_end(cmd, i + 2, "'")
            if end < 0:
                break
            text = re.sub(r"\\([\\'\"])", r"\1", cmd[i + 2:end])
            out.append(shlex.quote(text).replace("$", _LITERAL))
            word_start, i = False, end + 1
            continue
        if not quoted and ch == "#" and word_start:
            end = cmd.find("\n", i)
            end = len(cmd) if end < 0 else end
            out.append(re.sub(r"[\\'\"`;&|()]", " ", cmd[i:end]))
            i = end
            continue
        if ch == "`" or cmd.startswith("$(", i):
            start = i + 1 if ch == "`" else i + 2
            end = _escaped_end(cmd, start, "`") if ch == "`" else _substitution_end(cmd, start)
            if end < 0:
                raise ValueError("a command substitution that does not end")
            out.append(f"${_MARK}{len(runs)}{_MARK}")
            runs.append(cmd[start:end])
            word_start, i = False, end + 1
            continue
        if ch == '"':
            quoted = not quoted
        out.append(ch)
        word_start, i = ch in _WORD_BREAKS, i + 1
    out.append(cmd[i:])  # after a single quote that is not closed: as it was, for tokens() to split
    return "".join(out), runs


# Reserved words where a command begins. They run nothing: the command is what follows them.
_KEYWORDS = {"if", "then", "elif", "else", "while", "until", "do", "!", "{", "fi", "done", "esac", "}"}
# These begin words to loop over or to match, not a command.
_HEADS = {"for", "select", "case"}
# What they all open and close.
_OPENS = {"if": "if", "while": "loop", "until": "loop", "for": "loop", "select": "loop", "case": "case", "{": "{"}
_CLOSES = {"fi": "if", "done": "loop", "esac": "case", "}": "{"}
# In a branch, a case arm or a loop an assignment may not run, or may run again later.
_CONDITIONAL = {"if", "case", "loop"}
# Before these `p=x` stays set in POSIX mode: in sh, which is dash on Debian, and bash --posix.
_SPECIAL_BUILTINS = {":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set",
                     "shift", "source", "times", "trap", "unset"}
# A command is read once for each combination of the values its variables may hold, up to this.
_READINGS = 64


def _values(env: dict, name: str) -> tuple:
    """What a variable may hold. None stands for not set: where it is used, the word stays as
    it is written."""
    if name in env:
        return env[name]
    return (os.environ[name],) if name in os.environ else (None,)


def _union(*envs: dict) -> dict:
    """What the variables may hold when the command may have gone any of these ways. No env
    is changed once made, so one that is the same as another is skipped."""
    first = envs[0]
    if all(env is first for env in envs):
        return first
    out = dict(first)
    for env in envs[1:]:
        if env is first:
            continue
        for name in out.keys() - env.keys():
            out[name] = _merge(out[name], _values(env, name))
        for name, values in env.items():
            held = out.get(name)
            if held is not values and held != values:
                out[name] = _merge(_values(out, name), values)
    return out


def _merge(held: tuple, more: tuple) -> tuple:
    return held + tuple(v for v in more if v not in held)


def _readings(words: list[str], env: dict, inner: dict | None = None) -> list[list[str]]:
    """The words with the values of their variables put in, once for each combination of the
    values they may hold. Past _READINGS what the command is given cannot be told. A $ in single
    quotes is filled in from inner: in `p=x bash -c 'rm $p'` the shell that expands it has p=x."""
    def key(m: re.Match) -> str:  # $p and p's $ in single quotes are filled in apart
        return m.group(0)[0] + (m.group(1) or m.group(2))
    keys = list(dict.fromkeys(key(m) for word in words for m in _VAR.finditer(word)))
    choices = [_values(inner if k[0] == _LITERAL and inner is not None else env, k[1:]) for k in keys]
    if math.prod(len(c) for c in choices) > _READINGS:
        raise ValueError("variables that may hold more values than can be read")
    readings = []
    for combination in itertools.product(*choices):
        value = dict(zip(keys, combination))

        def put(m: re.Match) -> str:
            v = value[key(m)]
            return m.group(0) if v is None else v
        # after _VAR: `$` and what follows the mark is no name
        readings.append([_RUN.sub("", _VAR.sub(put, word)) for word in words])
    return readings


def _operators(run: str):
    """The operators in a run of them as the tokenizer gives it: `);` is `)` and `;`."""
    i = 0
    while i < len(run):
        op = run[i] if run[i] in "()" else next(o for o in _OPERATORS if run.startswith(o, i))
        yield op
        i += len(op)


class _Frame:
    """A part of a command that _read keeps apart: all of it, a ( ... ) or { ... }, a branch,
    case or loop, a <( ... ). What is set in it reaches the part around it only as values the
    variables may hold beside those they held before."""

    def __init__(self, kind: str, env: dict):
        self.kind = kind
        self.start = self.env = env    # what the variables held where it began, and after its lists so far
        self.words: list[str] = []     # of the command being read
        self.before = ""               # the operator before the next part of the current list: "", && or ||
        self.ok = self.failed = None   # what they hold if the list has so far succeeded, or failed
        self.pipe = None               # (what they held where a pipeline began, what its parts set)
        self.closed = None             # what a part closed just now left, until the operator after it
        self.case = ""                 # in a case: "head" up to `in`, "pattern" up to `)`, "arm" up to `;;`
        self.head = False              # its first command is the words of `for x in ...` or `case ... in`


def read(cmd: str, cwd: str = "") -> Command:
    cmd = _inline_heredocs(cmd.replace("\0", "").replace(_MARK, ""))
    out = Command(cwd)
    # The hook runs in the environment Claude Code gives its commands, so a variable set there
    # has the value the command saw (_values). Only what neither that nor the command itself sets is unknown.
    env = _read(cmd, out, {"HOME": (os.path.expanduser("~"),), "PWD": (cwd,)}, 0)
    visible = _SINGLE_QUOTED.sub("''", cmd)  # '$1' in an awk program is not a shell variable
    unset = {a or b for a, b in _VAR.findall(visible)} - set(env) - set(os.environ)
    out.dynamic = bool(_DYNAMIC.search(visible) or unset)
    return out


def _read(cmd: str, out: Command, env: dict, depth: int) -> dict:
    """Read cmd into out, with the variables holding what env says, and return what they may
    hold once it has run. Each holds a set of values it may have (#53): an assignment that
    certainly runs in this shell replaces them, and one that may not adds its value. It may not
    in a subshell, a pipeline, the background or a `bash -c` string, after && or ||, in a
    branch, case arm or loop, and as a prefix: `p=x cmd` sets p for cmd only."""
    frames = [_Frame("", env)]
    lost = False  # a closing word or `)` that fits nothing: from there on nothing is certain

    def env_in(f: _Frame) -> dict:
        """What the variables hold where the next part of f's current list runs."""
        if f.pipe:
            return f.pipe[0]
        return f.ok if f.before == "&&" else f.failed if f.before == "||" else f.env

    def part(f: _Frame, after: dict, op: str) -> None:
        """A part of f's current list has run and left the variables as after; op follows it."""
        start = env_in(f)
        if lost or f.kind in _CONDITIONAL:
            after = _union(start, after)
        if op in ("|", "|&"):  # each part of a pipeline runs in a subshell of its own
            f.pipe = (start, after if f.pipe is None else _union(f.pipe[1], after))
            return
        if f.pipe:  # zsh runs the last in this shell
            after, f.pipe = _union(*f.pipe, after), None
        if f.before == "&&":  # it ran if the list had succeeded so far
            f.ok, f.failed = after, _union(f.failed, after)
        elif f.before == "||":
            f.ok, f.failed = _union(f.ok, after), after
        else:
            f.ok = f.failed = after
        if op in ("&&", "||"):
            f.before = op
            return
        ran = _union(f.ok, f.failed)  # the list is over; after a &, in a subshell of its own
        f.env = _union(f.env, ran) if op == "&" else ran
        f.ok = f.failed = None
        f.before = ""

    def finish(f: _Frame, op: str) -> None:
        """The command f is reading ends at op."""
        words, after, f.words, f.closed = f.words, f.closed, [], None
        if f.head:  # words to loop over or to match, not a program
            f.head = False
            readings = _readings(words, env_in(f))
            for argv in readings:
                for arg in argv[1:2] if argv[0] == "case" else argv[3:]:  # case WORD in, for NAME in WORDS
                    _note_paths(arg.replace(_LITERAL, "$"), out.dirs, out.paths, out.globs)
            if words[0] != "case" and len(words) > 1 and re.fullmatch(r"[A-Za-z_]\w*", words[1]):
                # NAME holds each word in turn; without `in`, each argument the shell was given
                each = [a for argv in readings for a in argv[3:]] if words[2:3] == ["in"] else [None]
                part(f, {**env_in(f), words[1]: tuple(dict.fromkeys(each)) or (None,)}, ";")
            return
        if words:  # after a closed part, its redirections: `done > log`
            left = simple(words, env_in(f) if after is None else after)
            after = left if after is None else after
        if after is not None:
            part(f, after, op)

    def settle(f: _Frame) -> None:
        """f's last command ends, and with it its list, one left open (`a &&`) as well."""
        finish(f, ";")
        if f.before or f.pipe:
            part(f, env_in(f), ";")

    def open_(kind: str) -> None:
        f = frames[-1]
        frames.append(_Frame(kind, env_in(f) if f.closed is None else f.closed))

    def close(kind: str) -> None:
        nonlocal lost
        f = frames[-1]
        settle(f)
        if f.kind != kind:
            lost = True
            return
        frames.pop()
        if kind != "<(":  # a <( ... ) runs beside the command it is in, which goes on
            frames[-1].closed = _union(f.start, f.env)

    def operator(op: str) -> None:
        f = frames[-1]
        if f.case == "pattern":
            if op == ")":
                f.case = "arm"
            return  # `(` may begin a pattern, `|` joins two, and a line break ends none
        if op == "(":
            finish(f, ";")  # `f()`: the name of a function
            open_("(")
        elif op == ")":
            close("<(" if f.kind == "<(" else "(")
        elif op in (";;", ";&", ";;&") and f.case == "arm":
            finish(f, ";")
            f.case = "pattern"
        else:
            finish(f, op)

    def simple(words: list[str], start: dict) -> dict:
        """One simple command, read once for each combination of the values its variables may
        hold. Returns what they hold after it."""
        n = 0
        while n < len(words) and _ASSIGN.fullmatch(words[n]):
            n += 1
        scope = dict(start) if n else start  # what the command itself is run with
        for word in words[:n]:  # in turn: after `a=1 b=$a`, b is 1
            name, value = _ASSIGN.fullmatch(word).groups()
            scope[name] = tuple(dict.fromkeys(r[0] for r in _readings([value], scope)))
        rest = words[n:]
        after = scope if not rest or rest[0].startswith("#") else start  # p=x on its own, or before a comment
        evaluated = []
        for argv in _readings(rest, start, scope) if rest else []:
            if n and os.path.basename(argv[0]) in _SPECIAL_BUILTINS:
                after = _union(start, scope)
            fed = False
            while argv and os.path.basename(argv[0]) in _WRAPPERS:
                wrapper = os.path.basename(argv.pop(0))
                fed = fed or wrapper == "xargs"
                while argv and (argv[0].startswith("-") or argv[0].replace(".", "").isdigit()
                                or argv[0] == "{}" or _ASSIGN.fullmatch(argv[0])):
                    option = argv.pop(0)
                    if len(option) == 2 and option[0] == "-" and option[1] in _WRAPPERS[wrapper] and argv:
                        value = argv.pop(0)  # sudo -u root, timeout -s KILL, env -C dir
                        if (wrapper, option[1]) in _WRAPPER_CHDIR:
                            out.dirs.extend([canonical(value, d) for d in out.dirs[:8]])
                    elif len(option) > 2 and option[0] == "-" and option[1] != "-" and \
                            (wrapper, option[1]) in _WRAPPER_CHDIR:
                        out.dirs.extend([canonical(option[2:], d) for d in out.dirs[:8]])
            if argv:
                evaluated.append(_program(argv, fed, scope))
        evaluated = [e for e in evaluated if e is not None]
        if evaluated:  # eval runs its text in this shell
            after = _union(*evaluated, *([start] if n else []))
        return after

    def _program(argv: list[str], fed: bool, scope: dict) -> dict | None:
        """Record one program. For eval, returns what the variables hold after the text it runs."""
        fed = fed or any("$" in a for a in argv[1:])  # a $ in single quotes is text, not a value
        argv = [a.replace(_LITERAL, "$") for a in argv]
        out.programs.append(argv)
        out.program_fed.append(fed)
        out.program_dirs.append(list(out.dirs))
        paths: set[str] = set()
        globs: list[str] = []
        out.program_paths.append(paths)
        out.program_globs.append(globs)
        program = os.path.basename(argv[0])
        for i, arg in enumerate(argv[1:], 1):
            _note_paths(arg, out.dirs, paths, globs)
            if ">" in argv[i - 1] and set(argv[i - 1]) <= _REDIRECT_CHARS and not (
                    argv[i - 1].endswith("&") and (arg.isdigit() or arg == "-")):  # 2>&1 writes no file
                for target in expand_braces(arg):
                    out.writes.update(resolve(target, out.dirs))
        out.paths |= paths
        out.globs += globs
        if program == "cd":
            targets = [a for a in argv[1:] if not a.startswith("-")][:1] or \
                [home for home in _values(scope, "HOME") if home is not None]
            out.dirs.extend([canonical(t, d) for t in targets for d in out.dirs[:8]])
        if depth >= 3:
            return None
        if program in _TAKES_COMMAND:
            for i, arg in enumerate(argv[1:], 1):
                # the string after -c, and for a shell any argument with spaces in it: a script
                # given as a here-document arrives that way. A shell of its own: what it sets stays there.
                if re.fullmatch(r"-\w*c", argv[i - 1]) or (program in _SHELLS and re.search(r"\s", arg)):
                    _read(arg, out, scope, depth + 1)
        elif program == "eval":
            return _read(" ".join(argv[1:]), out, scope, depth + 1)
        elif program == "find":
            for i, arg in enumerate(argv):
                if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                    rest = argv[i + 1:]
                    end = next((j for j, a in enumerate(rest) if a in (";", "+", "\\;")), len(rest))
                    if rest[:end]:
                        _program(rest[:end], False, scope)
        return None

    text, runs = _lift_substitutions(cmd)
    for token in tokens(text):
        if token and set(token) <= _SEPARATORS:
            for op in _operators(token):
                operator(op)
            continue
        f = frames[-1]
        for n in _RUN.findall(token):
            # it runs before the command it is part of, and what it sets stays in it
            _read(runs[int(n)], out, env_in(f) if f.closed is None else f.closed, depth)
        token = token.strip("`")
        if f.case == "pattern":
            if token == "esac":
                close("case")
            continue  # a pattern is matched against, not run
        if f.case == "head" and token == "in":
            f.words.append(token)
            finish(f, ";")
            f.case = "pattern"
        elif not f.words and (token in _KEYWORDS or token in _HEADS):
            finish(f, ";")  # what was closed before it: `{ a; } then`
            if token in _CLOSES:
                close(_CLOSES[token])
            else:
                if token in _OPENS:
                    open_(_OPENS[token])
                if token in _HEADS:
                    frames[-1].words.append(token)
                    frames[-1].head = True
                if token == "case":
                    frames[-1].case = "head"
        elif token in ("<(", ">("):  # the program is given a file that the commands in it write or read
            f.words.append("/dev/fd/63")
            open_("<(")
        else:
            f.words.append(token)
    while True:
        settle(frames[-1])
        if len(frames) == 1:
            return frames[0].env
        close(frames[-1].kind)


def resolve(name: str, dirs: list[str]) -> list[str]:
    """A file name as canonical paths: one if it is absolute, else one per directory the command
    may be in (after `cd` inside a subshell or a pipeline the real one is not known)."""
    if os.path.isabs(os.path.expanduser(name)):
        return [canonical(name)]
    return [canonical(name, d) for d in dirs]


def _note_paths(arg: str, dirs: list[str], paths: set, globs: list) -> None:
    """Record the paths one argument names."""
    if "://" in arg and " " not in arg:
        return
    if arg and len(arg) <= 300 and not re.search(r"[\s'\"();]", arg):
        if arg.startswith("--"):
            forms = [arg.split("=", 1)[1]] if "=" in arg else []
        elif arg.startswith("-"):
            # A short option with its value attached: -o/path, and after other flags -sSLo/path.
            # Which letter takes the value depends on the program, so every tail is tried; a
            # tail that is not a path names nothing that exists and costs nothing.
            forms = [arg[k:] for k in range(2, min(len(arg), 14)) if len(arg) - k >= 2]
            forms += [arg.split("=", 1)[1]] if "=" in arg else []
        else:
            forms = [arg] + ([arg.split("=", 1)[1]] if "=" in arg else [])  # dd of=/path
        candidates = [c for form in forms if form for c in expand_braces(form)]
    else:
        candidates = _EMBEDDED.findall(arg[:200000])
    for cand in candidates:
        if _GLOB.search(cand):
            expanded = os.path.expanduser(cand)
            for d in [""] if os.path.isabs(expanded) else dirs:
                globs.append(os.path.normpath(os.path.join(d, expanded)))
        else:
            paths.update(resolve(cand, dirs))


# ---- what a command writes -----------------------------------------------------------------------
_CURL_VALUE_OPTS = set("AbcCdDeEFhHKmoPQrtTuUwxXyYz")  # short options whose value may be attached
_WGET_VALUE_OPTS = set("oaitTwQeUARDIXlBO P".replace(" ", ""))
_COPY = {"cp", "mv", "install", "ln", "rsync", "scp"}
_UNPACKERS = {"unzip", "7z"}
_TAR = {"tar", "bsdtar", "gtar"}
_OUTPUT_LONG = {"--output", "--out", "--output-file", "--outfile", "--output-document", "--dir", "--directory",
                "--output-dir", "--destination", "--target-directory"}


def _url_name(url: str) -> str:
    """The file name curl -O and wget give a download."""
    path = re.sub(r"^[a-z]+://[^/]*", "", url.split("?", 1)[0].split("#", 1)[0], flags=re.I)
    return path.rstrip("/").rsplit("/", 1)[-1] if path.strip("/") else "index.html"


def _curl_saves(args: list[str]) -> list[str]:
    names, out_dir, remote = [], "", False
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        if a.startswith("--"):
            name, eq, value = a[2:].partition("=")
            value = value if eq else following
            if name == "output-dir":
                out_dir = value
            elif name in ("output", "dump-header", "cookie-jar", "trace", "trace-ascii"):
                names.append(value)
            elif name in ("remote-name", "remote-name-all"):
                remote = True
        elif a.startswith("-") and len(a) > 1:
            for j, c in enumerate(a[1:], 1):
                if c == "O":
                    remote = True
                elif c in "oDc":
                    names.append(a[j + 1:] or following)
                    break
                elif c in _CURL_VALUE_OPTS:
                    break
    if remote:
        names += [_url_name(a) for a in args if "://" in a]
    return [os.path.join(out_dir, n) for n in names] if out_dir else names


def _wget_saves(args: list[str]) -> list[str]:
    document, prefix, recursive = "", "", False
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        name, eq, value = a.partition("=")
        if name == "--output-document":
            document = value if eq else following
        elif name == "--directory-prefix":
            prefix = value if eq else following
        elif name in ("--recursive", "--mirror", "--page-requisites"):
            recursive = True
        elif a.startswith("-") and not a.startswith("--"):
            for j, c in enumerate(a[1:], 1):
                if c == "O":
                    document = a[j + 1:] or following
                    break
                if c == "P":
                    prefix = a[j + 1:] or following
                    break
                if c in "rmp":
                    recursive = True
                elif c in _WGET_VALUE_OPTS:
                    break
    if document:
        return [document]
    urls = [a for a in args if "://" in a]
    names = [_url_name(u) for u in urls]
    if recursive:  # a tree named after the host
        names += [re.sub(r"^[a-z]+://([^/:]+).*", r"\1", u, flags=re.I) for u in urls]
    return [os.path.join(prefix, n) for n in names] if prefix else names


def _copy_destinations(args: list[str], dirs: list[str]) -> list[str]:
    target, names, skip = "", [], False
    for i, a in enumerate(args):
        if skip:
            skip = False
        elif a in ("-t", "--target-directory"):
            target, skip = (args[i + 1] if i + 1 < len(args) else ""), True
        elif a.startswith("--target-directory="):
            target = a.split("=", 1)[1]
        elif a.startswith("-t") and not a.startswith("--") and len(a) > 2:
            target = a[2:]
        elif not a.startswith("-"):
            names.append(a)
    if target:
        return [os.path.join(target, os.path.basename(src.rstrip("/"))) for src in names]
    if len(names) < 2:
        return []
    *sources, dest = names
    into_dir = dest.endswith("/") or len(sources) > 1 or any(os.path.isdir(p) for p in resolve(dest, dirs))
    return [os.path.join(dest, os.path.basename(src.rstrip("/"))) for src in sources] if into_dir else [dest]


def _output_options(program: str, args: list[str]) -> list[str]:
    """Where other programs are told to write: pandoc -o, sort -o, tar -C, unzip -d, gh ... -D.
    The letters mean something else elsewhere (`git -C dir` runs in dir, it does not write a
    file called dir), so each is taken only from the programs that use it for output."""
    def writes(option: str) -> bool:
        return (option in ("-o", "-O") or (option == "-C" and program in _TAR)
                or (option == "-D" and program == "gh") or (option == "-d" and program in _UNPACKERS))

    names = []
    for i, a in enumerate(args):
        following = args[i + 1] if i + 1 < len(args) else ""
        name, eq, value = a.partition("=")
        if name in _OUTPUT_LONG:
            names.append(value if eq else following)
        elif writes(a):
            names.append(following)
        elif not a.startswith("--") and len(a) > 2 and writes(a[:2]):
            names.append(a[2:])
    return names


def _clone_destination(program: str, args: list[str]) -> list[str]:
    names = [a for a in args if not a.startswith("-")]
    if program == "git" and "clone" in names:
        names = names[names.index("clone") + 1:]
    elif program == "gh" and names[:2] == ["repo", "clone"]:
        names = names[2:]
    else:
        return []
    if not names:
        return []
    return [names[1] if len(names) > 1 else re.sub(r"\.git$", "", names[0].rstrip("/").rsplit("/", 1)[-1])]


def written_paths(c: Command, clones: bool = True) -> set[str]:
    """Canonical paths the command says it writes: download options in every spelling (-o f, -of,
    --output=f, --output-dir, -O, wget's default name and -P), redirections and tee, the
    destination of cp/mv/dd, and the output options of other programs. A relative name is given
    under every directory the command may have been in at that point."""
    found = set(c.writes)
    for argv, dirs in zip(c.programs, c.program_dirs):
        program, args = os.path.basename(argv[0]), argv[1:]
        if program == "curl":
            names = _curl_saves(args)
        elif program == "wget":
            names = _wget_saves(args)
        elif program == "tee":
            names = [a for a in args if not a.startswith("-")]
        elif program in _COPY:
            names = _copy_destinations(args, dirs)
        elif program == "dd":
            names = [a[3:] for a in args if a.startswith("of=")]
        else:
            names = _output_options(program, args) + (_clone_destination(program, args) if clones else [])
        for name in names:
            for one in expand_braces(name):
                if one and not one.startswith("-"):
                    found.update(resolve(one, dirs))
    return found
