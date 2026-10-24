"""Just enough shell reading to see which programs a command runs and which files it names.

This is pattern reading, not a shell. It follows what a command says in plain sight: programs,
their arguments, `cd`, variables assigned in the same command, `bash -c '...'`, eval, `find -exec`,
the functions and traps it defines, command substitutions, redirections, globs. It cannot follow
a script that opens a file, an alias, or a value computed at run time; `Command.dynamic` says
when part of the command is of that kind.
"""

from __future__ import annotations

import fnmatch
import itertools
import math
import os
import re
import shlex

_REDIRECT_CHARS = set("<>&|")
# Programs that only run another program: the command after them is what counts. For each, the
# options whose value is a separate word, so that the value is not taken for the program.
_WRAPPERS = {"rtk": "", "sudo": "ughpCDRTU", "doas": "uC", "env": "uCS", "time": "fo", "nohup": "", "command": "",
             "builtin": "", "exec": "a", "nice": "n", "ionice": "cnp", "stdbuf": "ioe", "setsid": "",
             "timeout": "sk", "xargs": "IEnPLdsa", "watch": "n", "busybox": "", "toybox": "", "chronic": "",
             "unbuffer": "", "caffeinate": ""}
_WRAPPER_CHDIR = {("sudo", "D"), ("doas", "C"), ("sudo", "--chdir")}  # env: _env
# Programs that take a command line as the string after -c (bash -lc '...', script -qc '...').
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_TAKES_COMMAND = _SHELLS | {"su", "script"}
# Programs that take their program from stdin when they are given none: through a pipe, that is
# what the command before them prints.
_INTERPRETER = re.compile(r"(?:python|pypy|perl|ruby|node|nodejs|php|lua|tclsh|Rscript)[\d.]*")
_ASSIGN = re.compile(r"([A-Za-z_]\w*)=(.*)", re.S)
_VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
# \0 is a $ quoted against expansion (_LITERAL): text, which a shell may expand later (_wider)
_LITERAL_VAR = re.compile(r"\0(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
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
    """`python3 - <<'EOF' ... EOF` as `python3 - <<< '...'`. A here-document is text handed to
    the program, not shell: read line by line as commands, its first word of each line would be
    taken for a program and the paths it names would be lost. It stays a redirection, so that
    `p=x <<EOF` is still an assignment and nothing else (#57). With an unquoted marker the shell
    still runs the $(...) and `...` inside it, so those follow the text in the same word, where
    _walk reads them with the redirection."""
    def inline(m: re.Match) -> str:
        body, rest = m.group(4), m.group(3)
        runs = "" if m.group(1) else "".join(_substitutions_in(body))
        return f" <<< {shlex.quote(body)}{runs} {rest}"
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


# Every operator, longest first. A run of ; & | ( ) < > is split into these as the shell splits it:
# `a;>f` is a, ;, >, f, and in `(a)>f` the bracket closes before f is written.
_SHELL_OPS = sorted({"&&", "||", ";;&", ";;", ";&", "|&", ";", "&", "|", "(", ")", "<(", ">(", "<<<", "<<-", "<<",
                     "<>", "<&", ">&", ">>", ">|", "&>>", "&>", "<", ">"}, key=len, reverse=True)
# Those that join or end commands. The others are redirections, and part of the command they are in.
_LIST_OPS = {"&&", "||", ";;&", ";;", ";&", "|&", ";", "&", "|", "(", ")"}
_FD = re.compile(r"\d+|\{[A-Za-z_]\w*\}")              # 2>, {fd}>: the descriptor a redirection is for
_REDIRECTION = re.compile(r"[<>&]*[<>][<>&|]*")
_ARRAY = re.compile(r"[A-Za-z_]\w*\+?=")                 # NAME=( ... ), NAME+=( ... )
# An assignment as written: its name, any [index] and the = outside quotes. `'p=x'` and `p\=x` are programs.
_ASSIGN_WORD = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
_ASSIGN_PARTS = re.compile(r"([A-Za-z_]\w*)(\[[^\]]*\])?(\+?)=(.*)", re.S)


class _Token(str):
    """A word or an operator of a command line, and how it was written. The shell takes `done`
    for the end of a loop and `'done'` for a program, `p=x` for an assignment and `'p=x'` or
    `p\\=x` for a program, `>` for a redirection and `'>'` for an argument."""
    op = False     # an operator or a redirection, outside quotes
    fd = False     # the 2 of `2>`, the {fd} of `{fd}>`: part of the redirection after it
    plain = False  # nothing in it is quoted or escaped: if it is a reserved word, it is one
    raw = ""       # as written; empty where that cannot be told
    array = None   # NAME=( ... ): the words in the brackets


def _token(text: str, raw: str, **how) -> _Token:
    token = _Token(text)
    token.raw = raw
    token.__dict__.update(how)
    return token


def _unquote(raw: str) -> str:
    """A word as the shell has it once its quotes are taken away. A $ that was quoted or escaped
    against expansion is _LITERAL: `\\$p` and `"\\$p"` are the text $p, as '$p' is."""
    out, i = [], 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            nxt = raw[i + 1:i + 2]
            out.append(_LITERAL if nxt == "$" else "" if nxt == "\n" else nxt)
            i += 2
        elif ch == "'":
            end = raw.find("'", i + 1)
            end = len(raw) if end < 0 else end
            out.append(raw[i + 1:end].replace("$", _LITERAL))
            i = end + 1
        elif ch == '"':
            i += 1
            while i < len(raw) and raw[i] != '"':
                if raw[i] == "\\" and raw[i + 1:i + 2] in ("$", "`", '"', "\\", "\n"):
                    nxt = raw[i + 1]
                    out.append(_LITERAL if nxt == "$" else "" if nxt == "\n" else nxt)
                    i += 2
                else:
                    out.append(raw[i])
                    i += 1
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _array(text: str, i: int) -> tuple[list[str], int]:
    """The words of `NAME=( ... )` from just after its `(`, and where its `)` ends."""
    words = []
    while i < len(text):
        if text[i] in " \t\n" or text.startswith("\\\n", i):
            i += 1 if text[i] != "\\" else 2
        elif text[i] == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text[i] == ")":
            return words, i + 1
        elif text[i] in _WORD_BREAKS:
            break
        else:
            end = _word_end(text, i)
            if end < 0:
                break
            words.append(_unquote(text[i:end]))
            i = end
    raise ValueError("an array that cannot be read")


def _tokens(text: str) -> list[_Token]:
    """The words and operators of a command line, as _lift_substitutions leaves it. A line break
    is a `;`, and a `#` that begins a word begins a comment. From a quote that does not end, the
    shell runs nothing on that line; the rest is split at its operators all the same."""
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch in " \t" or text.startswith("\\\n", i):
            i += 1 if ch != "\\" else 2
        elif ch == "\n":
            out.append(_token(";", ch, op=True))
            i += 1
        elif ch == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif ch in "();<>|&":
            op = next(o for o in _SHELL_OPS if text.startswith(o, i))
            out.append(_token(op, op, op=True))
            i += len(op)
        else:
            end = _word_end(text, i)
            if end < 0:  # neither a reserved word nor an assignment can be told there
                for piece in re.findall(r"[();|&<>]+|[^\s();|&<>]+", text[i:]):
                    out.extend(_tokens(piece) if piece[0] in "();|&<>" else [_token(piece, "")])
                break
            raw = text[i:end]
            if text[end:end + 1] in ("<", ">") and _FD.fullmatch(raw):
                out.append(_token(raw, raw, fd=True))
            elif text[end:end + 1] == "(" and _ARRAY.fullmatch(raw):
                words, end = _array(text, end + 1)
                out.append(_token(raw, raw, array=words))
            else:
                out.append(_token(_unquote(raw), raw, plain=not re.search(r"[\\'\"]", raw)))
            i = end
    return out


def _parts(words: list[_Token]) -> tuple[list[_Token], list[_Token], list[_Token]]:
    """A simple command's assignments, its words, and its redirections with their targets.
    Redirections may stand anywhere, before and between the assignments too, and do not make a
    program of anything: `p=x >f` and `>f p=x` set p (#57). An assignment counts only before the
    first word and only as written (_ASSIGN_WORD)."""
    assigns, command, redirects, k = [], [], [], 0
    while k < len(words):
        word = words[k]
        k += 1
        if word.fd:
            redirects.append(word)
        elif word.op:
            redirects.append(word)
            if k < len(words) and not (words[k].op or words[k].fd):
                redirects.append(words[k])
                k += 1
        elif not command and (word.array is not None or _ASSIGN_WORD.match(word.raw)):
            assigns.append(word)
        else:
            command.append(word)
    return assigns, command, redirects


# Reserved words where a command begins. They run nothing: the command is what follows them.
_KEYWORDS = {"if", "then", "elif", "else", "while", "until", "do", "!", "{", "fi", "done", "esac", "}"}
# These begin words to loop over or to match, not a command.
_HEADS = {"for", "select", "case"}
# What they all open and close.
_OPENS = {"if": "if", "while": "loop", "until": "loop", "for": "loop", "select": "loop", "case": "case", "{": "{"}
_CLOSES = {"fi": "if", "done": "loop", "esac": "case", "}": "{"}
# What may follow `f()`: the body of a function is a compound command.
_BODIES = {"{", "if", "while", "until", "for", "select", "case"}
# In a branch, a case arm or a loop an assignment may not run, or may run again later.
_CONDITIONAL = {"if", "case", "loop"}
# Before these `p=x` stays set in POSIX mode: in sh, which is dash on Debian, and bash --posix.
_SPECIAL_BUILTINS = {":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set",
                     "shift", "source", "times", "trap", "unset"}
# Builtins that set the variables they are given, in this shell: `export p=x`.
_DECLARE = {"export", "declare", "typeset", "local", "readonly"}
# Builtins that give variables values the command does not show: `read p < f`.
_SETS = {"read", "mapfile", "readarray", "getopts", "printf", "unset"}
# After these, what follows in the part of the command they leave may not run.
_LEAVES = {"return", "break", "continue", "exit"}
# A command is read once for each combination of the values its variables may hold, up to this.
_READINGS = 64
# Times a loop is read again because a pass may leave a value the next begins with (#56), in one
# command at most.
_PASSES = 32
# Shells inside shells (bash -c, eval) read, at most; functions inside functions; and tokens
# read in all, loops and calls counted each time. Past any of them the command cannot be read.
_DEPTH = 4
_CALLS = 8
_WORK = 100000


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


def _exported(env: dict, names=()) -> dict:
    """What a program this shell starts finds in its environment. A variable Claude Code gave
    the command, and one exported to the program (names: `p=x bash -c ...`), holds what it holds
    here; any other the command set may not have been exported, and may not be set there."""
    return {name: values if name in names or name in os.environ else _merge(values, (None,))
            for name, values in env.items()}


def _reset(env: dict) -> dict:
    """The environment sudo, doas and su give a program: they keep some variables and set or
    drop others, by their own rules. Each may hold what it held, or not be set."""
    return {name: _merge(_values(env, name), (None,)) for name in {*env, *os.environ}}


def _cleared(env: dict) -> dict:
    """`env -i`: nothing set but what env sets after it."""
    return {name: (None,) for name in {*env, *os.environ}}


# $NAME, ${NAME}, and ${NAME} with an operator after the name: ${p:-x}, ${p%/*}, ${p//a/b}, ${p:1:2}
_EXPANSION = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*)|\{([A-Za-z_]\w*)"
                        r"(:?[-=+?]|##?|%%?|/[/#%]?|\^\^?|,,?|:)([^{}]*)\})")
# ${p:=x} and ${p=x} give p the value x where it is not set, in this shell
_DEFAULT = re.compile(r"\$\{([A-Za-z_]\w*):?=([^{}]*)\}")


# Not set: beside None, which stands for not set or not known, where the two read differently.
_UNSET = object()


def _param(value: str | None, op: str, arg: str) -> str | None:
    """What ${NAME<op><arg>} gives for a NAME that holds value (None: not set), or None where
    that cannot be told: the word then stays as it is written, and counts as fed from elsewhere."""
    if re.search(r"[$`\\'\"" + _LITERAL + _MARK + "]", arg):
        return None
    unset = value is None
    null = unset or value == ""
    if op in ("-", "="):
        return arg if unset else value
    if op in (":-", ":="):
        return arg if null else value
    if op in ("+", ":+"):
        return "" if (unset if op == "+" else null) else arg
    if unset or op in ("?", ":?"):
        return value
    if op in ("#", "##"):  # the shortest or longest start that matches, taken off
        for k in range(len(value) + 1) if op == "#" else range(len(value), -1, -1):
            if fnmatch.fnmatchcase(value[:k], arg):
                return value[k:]
        return value
    if op in ("%", "%%"):  # the shortest or longest end
        for k in range(len(value), -1, -1) if op == "%" else range(len(value) + 1):
            if fnmatch.fnmatchcase(value[k:], arg):
                return value[:k]
        return value
    if op[0] == "/":
        pattern, _, put = arg.partition("/")
        if not pattern:
            return value
        rx = fnmatch.translate(pattern)[:-2]  # (?s:...) without its \Z
        if op == "/#":
            rx = "^" + rx
        elif op == "/%":
            rx = rx + "$"
        return re.sub(rx, put.replace("\\", "\\\\"), value, count=0 if op == "//" else 1)
    if op in ("^", "^^", ",", ",,"):
        if arg:
            return None
        case = str.upper if op[0] == "^" else str.lower
        return case(value) if len(op) == 2 else case(value[:1]) + value[1:]
    if op == ":":  # ${p:offset} and ${p:offset:length}
        m = re.fullmatch(r"\s*\(?\s*(-?\d+)\s*\)?\s*(?::\s*(-?\d+)\s*)?", arg)
        if not m:
            return None
        start = int(m.group(1))
        start = max(len(value) + start, 0) if start < 0 else start
        if m.group(2) is None:
            return value[start:]
        length = int(m.group(2))
        return value[start:start + length] if length >= 0 else value[start:len(value) + length]
    return None


def _readings(words: list[str], env: dict, envs: list[dict] | None = None) -> list[list[str]]:
    """The words with the values of their variables put in, once for each combination of the
    values they may hold; envs gives each word an env of its own. Past _READINGS what the command
    is given cannot be told. A $ in single quotes (_LITERAL) is not filled in: it is text, and a
    shell that reads it later, in `bash -c` or eval, has variables of its own then (#58)."""
    envs = envs or [env] * len(words)
    held: dict[tuple, tuple] = {}
    for word, e in zip(words, envs):
        for m in _EXPANSION.finditer(word):
            name = m.group(1) or m.group(2) or m.group(3)
            key = (id(e), name)
            held.setdefault(key, _values(e, name))
            if m.group(4) and None in held[key] and _UNSET not in held[key]:
                held[key] += (_UNSET,)  # ${p:-x} on what may not be known: read as unknown, and as not set
    keys = list(held)
    if math.prod(len(held[k]) for k in keys) > _READINGS:
        raise ValueError("variables that may hold more values than can be read")
    readings = []
    for combination in itertools.product(*(held[k] for k in keys)):
        value = dict(zip(keys, combination))
        reading = []
        for word, e in zip(words, envs):
            def put(m: re.Match, e=e) -> str:
                v = value[(id(e), m.group(1) or m.group(2) or m.group(3))]
                if m.group(4):
                    v = None if v is None else _param(None if v is _UNSET else v, m.group(4), m.group(5))
                return m.group(0) if v is None or v is _UNSET else v
            # after _EXPANSION: `$` and what follows the mark is no name
            reading.append(_RUN.sub("", _EXPANSION.sub(put, word)))
        readings.append(reading)
    return readings


def _wider(arg: str, env: dict) -> list[str]:
    """The argument as text, and again with each $ in single quotes in it filled in from env.
    A program may hand such text to a shell of its own (python's os.system, an alias, a trap), and
    what the variables hold there cannot be told; the paths it names are read as naming what the
    command's variables hold. Wider than the truth."""
    names = list(dict.fromkeys(m.group(1) or m.group(2) for m in _LITERAL_VAR.finditer(arg)))
    texts = [arg.replace(_LITERAL, "$")]
    choices = [tuple(v for v in _values(env, name) if v is not None) or (None,) for name in names]
    if math.prod(len(c) for c in choices) > _READINGS:
        raise ValueError("variables that may hold more values than can be read")
    for combination in itertools.product(*choices) if names else ():
        value = dict(zip(names, combination))

        def put(m: re.Match) -> str:
            v = value[m.group(1) or m.group(2)]
            return m.group(0) if v is None else v
        texts.append(_LITERAL_VAR.sub(put, arg).replace(_LITERAL, "$"))
    return list(dict.fromkeys(texts))


def _grows(after: dict, before: dict) -> bool:
    """after holds a value that before does not."""
    return any(not set(_values(after, name)) <= set(_values(before, name)) for name in after)


def _snapshot(out: Command) -> tuple:
    return len(out.programs), len(out.globs), len(out.dirs), set(out.paths), set(out.writes)


def _restore(out: Command, snapshot: tuple) -> None:
    """out as it was at the snapshot: what was read since is read again."""
    programs, globs, dirs, paths, writes = snapshot
    for each in (out.programs, out.program_dirs, out.program_paths, out.program_globs, out.program_fed):
        del each[programs:]
    del out.globs[globs:]
    del out.dirs[dirs:]
    out.paths.clear()
    out.paths.update(paths)
    out.writes.clear()
    out.writes.update(writes)


# Long options of wrappers that take their value as the next word, and options that name a file the
# wrapper writes.
_WRAPPER_LONG = {"sudo": {"--user", "--group", "--host", "--prompt", "--chdir", "--chroot", "--close-from",
                          "--command-timeout", "--other-user", "--role", "--type", "--login-class"},
                 "timeout": {"--signal", "--kill-after"}, "nice": {"--adjustment"},
                 "ionice": {"--class", "--classdata", "--pid", "--pgid", "--uid"},
                 "stdbuf": {"--input", "--output", "--error"}, "time": {"--format", "--output"},
                 "xargs": {"--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-lines", "--max-chars",
                           "--process-slot-var"}, "watch": {"--interval"}}
_WRAPPER_WRITES = {("time", "o"), ("time", "--output")}
_ENV_LONG = {"--ignore-environment": "i", "--null": "0", "--debug": "v", "--unset": "u", "--chdir": "C",
             "--split-string": "S", "--argv0": "a"}


def _env(argv: list[str], child: dict, out: Command) -> tuple[list[str], dict]:
    """env's options and NAME=VALUE operands: the program after them, and what it is run with
    (#59). The variables env sets, unsets (-u) or clears (-i) are the program's, not this shell's.
    An option this does not know may change what the program is or what it finds, and cannot be
    read."""
    options = True
    while argv:
        word = argv.pop(0)
        if options and word == "--":  # NAME=VALUE operands may still follow
            options = False
            continue
        if options and word == "-":
            child = _cleared(child)
            continue
        if not (options and word.startswith("-")):
            if "=" not in word[1:]:
                argv.insert(0, word)
                break
            name, value = word.split("=", 1)
            child = {**child, name: (value,)}
            continue
        if word.startswith("--"):
            option, eq, value = word.partition("=")
            if option in ("--block-signal", "--default-signal", "--ignore-signal", "--list-signal-handling"):
                continue
            if option in ("--help", "--version"):
                return [], child
            if option not in _ENV_LONG:
                raise ValueError(f"env {option}")
            if option in ("--unset", "--chdir", "--split-string", "--argv0") and not eq:
                if not argv:
                    raise ValueError(f"env {option}")
                value = argv.pop(0)
            given = [(_ENV_LONG[option], value)]
        else:
            given, k = [], 1
            while k < len(word):
                letter = word[k]
                if letter in "i0v":
                    given.append((letter, ""))
                    k += 1
                    continue
                if letter not in "uCSa" or not (word[k + 1:] or argv):
                    raise ValueError(f"env -{letter}")
                given.append((letter, word[k + 1:] or argv.pop(0)))
                break
        for letter, value in given:
            if letter == "i":
                child = _cleared(child)
            elif letter == "u":
                child = {**child, value: (None,)}
            elif letter == "C":
                out.dirs.extend([canonical(value, d) for d in out.dirs[:8]])
            elif letter == "S":  # the string is split into words and read on as env's
                if re.search(r"[$\\" + _LITERAL + "]", value):
                    raise ValueError("env -S with what env itself expands")
                argv[0:0] = shlex.split(value, comments=True)
    return argv, child


def _unwrap(argv: list[str], child, out: Command) -> tuple[list[str], bool, object]:
    """The program the wrappers in front of it run, whether its arguments come from elsewhere
    (xargs), and what it finds in its environment. That is made only where it is needed: child is
    a function that makes it, and so is what is returned."""
    fed = False
    while argv and os.path.basename(argv[0]) in _WRAPPERS:
        wrapper = os.path.basename(argv.pop(0))
        if wrapper == "env":
            argv, env = _env(argv, child(), out)
            child = lambda env=env: env
            continue
        fed = fed or wrapper == "xargs"
        if wrapper in ("sudo", "doas"):
            env = _reset(child())
            child = lambda env=env: env
        run_words = edit = False
        while argv and (argv[0].startswith("-") or argv[0].replace(".", "").isdigit()
                        or argv[0] == "{}" or _ASSIGN.fullmatch(argv[0])):
            option = argv.pop(0)
            if option == "--":
                break
            if _ASSIGN.fullmatch(option):
                if wrapper == "sudo":  # sudo p=x cmd: where the policy lets it, cmd has p=x
                    name, value = _ASSIGN.fullmatch(option).groups()
                    env = {**child(), name: (value,)}
                    child = lambda env=env: env
                continue
            run_words = run_words or option in ("-x", "--exec")
            edit = edit or (wrapper == "sudo" and option in ("-e", "--edit"))
            if option.startswith("--"):
                name, eq, value = option.partition("=")
                if not eq and name in _WRAPPER_LONG.get(wrapper, ()) and argv:
                    eq, value = "=", argv.pop(0)
                key = (wrapper, name)
            elif len(option) == 2 and option[1] in _WRAPPERS[wrapper] and argv:
                eq, value, key = "=", argv.pop(0), (wrapper, option[1])  # sudo -u root, timeout -s KILL
            else:
                eq, value, key = "=", option[2:], (wrapper, option[1:2])  # -D/dir, -o/file
            if eq and value and key in _WRAPPER_CHDIR:
                out.dirs.extend([canonical(value, d) for d in out.dirs[:8]])
            if eq and value and key in _WRAPPER_WRITES:
                out.writes.update(resolve(value, out.dirs))
        if edit:
            argv = ["sudoedit", *argv]
        if wrapper == "watch" and argv and not run_words:  # watch hands its words to sh -c
            argv = ["sh", "-c", " ".join(argv)]
    return argv, fed, child


class _Context:
    """What the reading of one command keeps across the texts it reads: the functions it defines,
    the traps it sets, and how much it has read."""

    def __init__(self, out: Command):
        self.out = out
        self.functions: dict[str, tuple] = {}  # name: (the tokens of its body, the substitutions they mark)
        self.defined = 0                       # functions defined or changed so far
        self.calls: list[str] = []             # the functions being read, innermost last
        self.called: set[str] = set()          # and those read where they are called
        self.traps: dict[tuple, list] = {}     # (text, depth): [what the variables may hold while it may run, signals]
        self.work = 0

    def define(self, name: str, body: list, runs: list) -> None:
        if self.functions.get(name) != (body, runs):
            self.functions[name] = (body, runs)
            self.defined += 1

    def finish(self, end: dict) -> None:
        """What runs after the command has been read, or at a time it does not show. A trap runs
        when its signal comes or the shell exits (end): it is read with all the variables may hold
        from where it was set, and one that changes them at another time than the exit, the
        command cannot be read with. A function that is defined and not called where this can
        see it may still be called (a name made at run time, a sourced file): it is read once, with
        what the variables hold at the end."""
        for held in self.traps.values():
            held[0] = _union(held[0], end)
        done = set()
        while len(done) < len(self.traps) or self.functions.keys() - self.called:
            for key in [k for k in self.traps if k not in done]:
                done.add(key)
                env, signals = self.traps[key]
                after = _read(key[0], self, env, key[1])
                if signals - {"EXIT", "0"} and _grows(after, env):
                    raise ValueError("a trap that changes variables at a time that cannot be told")
            for name in list(self.functions.keys() - self.called):
                self.called.add(name)
                _walk(*self.functions[name], self, end, 0)


class _Frame:
    """A part of a command that _walk keeps apart: all of it, a ( ... ) or { ... }, a branch,
    case or loop, a <( ... ). What is set in it reaches the part around it only as values the
    variables may hold beside those they held before."""

    def __init__(self, kind: str, env: dict):
        self.kind = kind
        self.start = self.env = env    # what the variables held where it began, and after its lists so far
        self.words: list[_Token] = []  # of the command being read
        self.before = ""               # the operator before the next part of the current list: "", && or ||
        self.ok = self.failed = None   # what they hold if the list has so far succeeded, or failed
        self.pipe = None               # (what they held where a pipeline began, what its parts set)
        self.closed = None             # what a part closed just now left, until the operator after it
        self.case = ""                 # in a case: "head" up to `in`, "pattern" up to `)`, "arm" up to `;;`
        self.head = False              # its first command is the words of `for x in ...` or `case ... in`
        self.entry = env               # in a loop: what the variables hold where a pass begins
        self.at = 0                    # and the token it begins at, with out as it was there
        self.snapshot = None
        self.defined = 0               # and the functions defined there
        self.function = None           # the body of this function, being defined: it runs where it is called
        self.cut = False               # a return, break, continue or exit was read in it: what follows may not run


def read(cmd: str, cwd: str = "") -> Command:
    cmd = cmd.replace("\0", "").replace(_MARK, "")
    out = Command(cwd)
    ctx = _Context(out)
    # The hook runs in the environment Claude Code gives its commands, so a variable set there
    # has the value the command saw (_values). Only what neither that nor the command itself sets is unknown.
    env = _read(cmd, ctx, {"HOME": (os.path.expanduser("~"),), "PWD": (cwd,)}, 0)
    ctx.finish(env)
    visible = _SINGLE_QUOTED.sub("''", _inline_heredocs(cmd))  # '$1' in an awk program is not a shell variable
    unset = {a or b for a, b in _VAR.findall(visible)} - set(env) - set(os.environ)
    out.dynamic = bool(_DYNAMIC.search(visible) or unset)
    return out


def _read(cmd: str, ctx: _Context, env: dict, depth: int, inline: bool = True) -> dict:
    """Read cmd into ctx.out, with the variables holding what env says, and return what they may
    hold once it has run."""
    text, runs = _lift_substitutions(_inline_heredocs(cmd) if inline else cmd)
    return _walk(_tokens(text), runs, ctx, env, depth)


def _walk(toks: list[_Token], runs: list[str], ctx: _Context, env: dict, depth: int) -> dict:
    """Read the tokens into ctx.out, with the variables holding what env says, and return what
    they may hold once they have run. Each holds a set of values it may have (#53): an assignment
    that certainly runs in this shell replaces them, and one that may not adds its value. It may
    not in a subshell, a pipeline, the background or a `bash -c` string, after && or ||, in a
    branch, case arm or loop, after a return, break, continue or exit, and as a prefix: `p=x cmd`
    sets p for cmd only."""
    out = ctx.out
    frames = [_Frame("", env)]
    lost = False     # a closing word or `)` that fits nothing: from there on nothing is certain
    silent = 0       # in the body of a function being defined: read for where it ends, not run
    defining = None  # the name of a function whose body comes next
    i = 0            # the token being read
    carry = None     # (a loop's first token, what its passes may leave): it is read again with that
    passes = 0
    piped = False    # the command being read is given its input by the one before it, through a pipe

    def substitutions(word: str, env: dict) -> None:
        """Each $(...) in the word runs before the word is used, and what it sets stays in it."""
        if not silent:
            for n in _RUN.findall(word):
                _read(runs[int(n)], ctx, env, depth, inline=False)

    def env_in(f: _Frame) -> dict:
        """What the variables hold where the next part of f's current list runs."""
        if f.pipe:
            return f.pipe[0]
        return f.ok if f.before == "&&" else f.failed if f.before == "||" else f.env

    def part(f: _Frame, after: dict, op: str) -> None:
        """A part of f's current list has run and left the variables as after; op follows it."""
        start = env_in(f)
        if lost or f.cut or f.kind in _CONDITIONAL:
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
        nonlocal piped
        words, after, f.words, f.closed = f.words, f.closed, [], None
        if silent:
            f.head = False
            return
        if f.head:  # words to loop over or to match, not a program
            f.head = False
            for word in words:
                substitutions(word, env_in(f))
            readings = _readings(words, env_in(f))
            for argv in readings:
                for arg in argv[1:2] if argv[0] == "case" else argv[3:]:  # case WORD in, for NAME in WORDS
                    _note_paths(arg.replace(_LITERAL, "$"), out.dirs, out.paths, out.globs)
            if words[0] != "case" and len(words) > 1 and re.fullmatch(r"[A-Za-z_]\w*", words[1]):
                # NAME holds each word in turn; without `in`, each argument the shell was given
                each = [a for argv in readings for a in argv[3:]] if words[2:3] == ["in"] else [None]
                part(f, {**env_in(f), words[1]: tuple(dict.fromkeys(each)) or (None,)}, ";")
                f.entry = f.env
            return
        if words:  # after a closed part, its redirections: `done > log`
            piped = f.pipe is not None
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
        nonlocal defining, silent
        f = frames[-1]
        frames.append(_Frame(kind, env_in(f) if f.closed is None else f.closed))
        if defining is not None:
            frames[-1].function, frames[-1].at, defining = defining, i - 1, None
            silent += 1

    def close(kind: str) -> None:
        nonlocal lost, silent
        f = frames[-1]
        settle(f)
        if f.kind != kind:
            lost = True
            return
        frames.pop()
        if f.function is not None:  # defining a function runs nothing; its body is read where it is called (#60)
            silent -= 1
            ctx.define(f.function, toks[f.at:i], runs)
            frames[-1].closed = f.start
        elif kind != "<(":  # a <( ... ) runs beside the command it is in, which goes on
            frames[-1].closed = _union(f.start, f.env)

    def again(f: _Frame) -> bool:
        """At the `done` of loop f. When a pass may leave a value that the pass after it begins
        with and this one did not, or defines a function, the loop is read again from its first
        word with that (#56), and whatever was read in it is read anew. True if it is."""
        nonlocal i, carry, passes
        settle(f)
        if silent or (not _grows(f.env, f.entry) and ctx.defined == f.defined):
            return False
        passes += 1
        if passes > _PASSES:
            raise ValueError("a loop whose variables do not settle")
        _restore(out, f.snapshot)
        frames.pop()
        carry, i = (f.at, f.env), f.at
        return True

    def leave(word: str) -> None:
        """return, break, continue, exit: what follows them in the frames they leave may not run."""
        for f in reversed(frames):
            f.cut = True
            if (word in ("break", "continue") and f.kind == "loop") or (word == "exit" and f.kind == "("):
                break

    def operator(op: str) -> None:
        nonlocal i, defining
        f = frames[-1]
        if f.case == "pattern":
            if op == ")":
                f.case = "arm"
            return  # `(` may begin a pattern, `|` joins two, and a line break ends none
        if op == "(" and len(f.words) == 1 and not f.head and toks[i:i + 1] == [")"] and toks[i].op:
            defining, f.words = f.words[0], []  # `f()`: a function, and its body comes next
            i += 1
        elif op == "(":
            finish(f, ";")
            open_("(")
        elif op == ")":
            close("<(" if f.kind == "<(" else "(")
        elif op in (";;", ";&", ";;&") and f.case == "arm":
            finish(f, ";")
            f.case = "pattern"
        else:
            finish(f, op)

    def assign(word: _Token, env: dict, expand: bool) -> tuple[str, tuple]:
        """NAME=VALUE, NAME+=VALUE, NAME[I]=VALUE, NAME=(A B): the name, and the values it may
        hold after. What it is given is a path the command names: a program fed from elsewhere may
        be given it (_note_paths)."""
        name, index, plus, value = _ASSIGN_PARTS.fullmatch(word).groups()
        if word.array is not None:
            for element in word.array:
                substitutions(element, env)
            values = tuple(dict.fromkeys(r[0] for e in word.array for r in _readings([e], env))) or ("",)
        else:
            if expand:
                substitutions(value, env)
            values = tuple(dict.fromkeys(r[0] for r in _readings([value], env)))
        for v in values:
            _note_paths(v.replace(_LITERAL, "$"), out.dirs, out.paths, out.globs)
        if plus and not index and word.array is None:  # p+=x: x after each value p may hold, and after ${p}
            values = tuple(dict.fromkeys((old if old is not None else "${" + name + "}") + v
                                         for old in _values(env, name) for v in values))
        elif index or plus:  # one element, or more: the others are still there
            values = _merge(_values(env, name), values)
        return name, values

    def declare(command: list[_Token], env: dict) -> dict | None:
        """export, declare, local, readonly, typeset: the variables they set, whose values are
        expanded before they run, and with `builtin` or `command` in front of them. A name
        reference (-n) the command cannot be read with."""
        k = 0
        while k + 1 < len(command) and command[k].plain and command[k] in ("builtin", "command"):
            k += 1
        builtin = command[k]
        if not (builtin.plain and builtin in _DECLARE):
            return None
        declared = {}
        for word in command[k + 1:]:
            if word.startswith(("-", "+")) and word.array is None:
                if builtin != "export" and "n" in word[1:]:
                    raise ValueError("a name reference")
                if "f" in word[1:] or "F" in word[1:]:
                    return declared  # functions, not variables
            elif word.array is not None or _ASSIGN_PARTS.fullmatch(word):
                name, values = assign(word, env, False)
                declared[name] = values
            elif builtin in ("local", "declare", "typeset") and re.fullmatch(r"[A-Za-z_]\w*", word):
                declared[word] = _merge(_values(env, word), (None,))  # in a function: a variable of its own
        return declared

    def sets(argv: list[str], env: dict) -> dict:
        """read, mapfile, getopts, printf -v, unset: variables given values the command does not show."""
        program, args = argv[0], argv[1:]
        if program == "unset" and "-f" in args:
            return env
        if program in ("mapfile", "readarray") and any(a.startswith("-") and "C" in a for a in args):
            raise ValueError("a callback the shell runs")
        names = [a for a in args if re.fullmatch(r"[A-Za-z_]\w*", a)]
        if program == "printf":
            names = [a[2:] or (args[k + 1] if k + 1 < len(args) else "") for k, a in enumerate(args) if a.startswith("-v")]
        elif program in ("mapfile", "readarray"):
            names = names[-1:] or ["MAPFILE"]
        elif program == "getopts":
            names = args[1:2]
        elif program == "read":
            names = names or ["REPLY"]
        env = dict(env)
        for name in names:
            env[name] = (None,) if program == "unset" else _merge(_values(env, name), (None,))
        return env

    def trap(args: list[str], env: dict) -> None:
        """trap TEXT SIGNALS: TEXT runs later, and is read later (_Context.run_traps)."""
        if args[:1] == ["--"]:
            args = args[1:]
        if len(args) < 2 or args[0] in ("", "-", "-p", "-l"):
            return
        key = (args[0].replace(_LITERAL, "$"), depth)
        signals = {s.upper().removeprefix("SIG") for s in args[1:]}
        held = ctx.traps.get(key)
        ctx.traps[key] = [_union(held[0], env), held[1] | signals] if held else [env, signals]

    def call(name: str, env: dict) -> dict:
        """A function runs its body in this shell, with what the variables hold where it is
        called (#60). What it sets may stay after it, beside what they held before."""
        if len(ctx.calls) >= _CALLS:
            raise ValueError("functions that call each other deeper than can be read")
        body, body_runs = ctx.functions[name]
        ctx.calls.append(name)
        ctx.called.add(name)
        try:
            return _union(env, _walk(body, body_runs, ctx, env, depth))
        finally:
            ctx.calls.pop()

    def simple(words: list[_Token], start: dict) -> dict:
        """One simple command, read once for each combination of the values its variables may
        hold. Returns what they hold after it: ${p:=x} in it may give p the value x."""
        after = command_(words, start)
        for name, value in {m.groups() for word in words for m in _DEFAULT.finditer(word)}:
            plain = not re.search(r"[$`\\'\"" + _LITERAL + _MARK + "]", value)
            after = {**after, name: _merge(_values(after, name), (value if plain else None,))}
        return after

    def command_(words: list[_Token], start: dict) -> dict:
        for held in ctx.traps.values():  # a trap set before may run while this does
            held[0] = _union(held[0], start)
        assigns, command, redirects = _parts(words)
        for word in command:  # the shell expands these first, with what the variables held before
            substitutions(word, start)
        scope = dict(start) if assigns else start  # what the command itself is run with
        for word in assigns:  # then these in turn: after `a=1 b=$a`, b is 1, and in b=$(...) too (#55)
            name, values = assign(word, scope, True)
            scope[name] = values
        # A redirection, bash expands after the assignments of a command without a program, dash before.
        late = _union(start, scope) if assigns and redirects else start
        for word in redirects:
            substitutions(word, late)
        if not command:  # p=x, p=x >f, >f p=x: the assignments stay in this shell (#57)
            for argv in _readings(redirects, late) if redirects else []:
                _program(argv, False, scope, lambda: scope)
            return scope
        declared = declare(command, start)
        made = []

        def child() -> dict:  # what a program the command starts finds in its environment
            if not made:
                made.append(_exported(scope, {_ASSIGN_PARTS.fullmatch(w).group(1) for w in assigns}))
            return made[0]
        envs = [start] * len(command) + [late] * len(redirects)
        return _union(*[run(argv, start, scope, child, declared, bool(assigns))
                        for argv in _readings(command + redirects, start, envs)])

    def run(argv: list[str], start: dict, scope: dict, child, declared: dict | None, prefixed: bool) -> dict:
        """One reading of a simple command: what the variables hold after it."""
        while len(argv) > 1 and argv[0] == "":  # a variable that holds nothing, unquoted, is no word
            argv = argv[1:]
        name, after = argv[0], start
        if prefixed and os.path.basename(name) in _SPECIAL_BUILTINS:
            after = _union(start, scope)
        if declared is not None:
            after = {**after, **declared}
        elif name in _SETS:
            after = sets(argv, after)
        elif name in _LEAVES:
            leave(name)
        elif name == "trap":
            trap(argv[1:], start)
        if name in ctx.functions:
            after = _union(after, call(name, scope))
        elif "$" in name:  # a program picked at run time may be any of the functions
            for other in [f for f in ctx.functions if f not in ctx.calls]:
                after = _union(after, call(other, scope))
        argv, fed, child = _unwrap(argv, child, out)
        if argv:
            evaluated = _program(argv, fed, scope, child)
            if evaluated is not None:  # eval runs its text in this shell
                after = _union(evaluated, start) if prefixed else evaluated
        return after

    def nest(text: str, env: dict) -> dict:
        if depth >= _DEPTH:
            raise ValueError("shells inside shells deeper than can be read")
        return _read(text, ctx, env, depth + 1)

    def _program(argv: list[str], fed: bool, scope: dict, child) -> dict | None:
        """Record one program. For eval, returns what the variables hold after the text it runs.
        A shell it starts (bash -c) is read with child(), what that shell finds in its environment."""
        fed = fed or any("$" in a for a in argv)  # a $ in single quotes (_LITERAL) is text, not a value
        raw = [a.replace(_LITERAL, "$") for a in argv]
        operands = raw[1:]  # up to its redirections, which _parts puts after its words
        for k, a in enumerate(operands):
            if _REDIRECTION.fullmatch(a) or (_FD.fullmatch(a) and _REDIRECTION.fullmatch((operands[k + 1:] or [""])[0])):
                operands = operands[:k]
                break
        if piped and _INTERPRETER.fullmatch(os.path.basename(raw[0])) and \
                all(a.startswith("-") and a not in ("-c", "-e", "-E", "-m", "-r") for a in operands):
            fed = True  # `echo '...' | python3`: its program, and the paths in it, come through the pipe
        out.programs.append(raw)
        out.program_fed.append(fed)
        out.program_dirs.append(list(out.dirs))
        paths: set[str] = set()
        globs: list[str] = []
        out.program_paths.append(paths)
        out.program_globs.append(globs)
        program = os.path.basename(raw[0])
        for i, arg in enumerate(argv[1:], 1):
            for text in _wider(arg, scope):
                _note_paths(text, out.dirs, paths, globs)
            if ">" in raw[i - 1] and set(raw[i - 1]) <= _REDIRECT_CHARS and not (
                    raw[i - 1].endswith("&") and (raw[i].isdigit() or raw[i] == "-")):  # 2>&1 writes no file
                for target in expand_braces(raw[i]):
                    out.writes.update(resolve(target, out.dirs))
        out.paths |= paths
        out.globs += globs
        if program == "cd":
            targets = [a for a in raw[1:] if not a.startswith("-")][:1] or \
                [home for home in _values(scope, "HOME") if home is not None]
            out.dirs.extend([canonical(t, d) for t in targets for d in out.dirs[:8]])
        if program in _SHELLS and piped and not any(re.fullmatch(r"-\w*c", a) for a in raw[1:]):
            raise ValueError("a shell that reads its commands from a pipe")  # `echo 'rm ...' | bash`
        if program in _TAKES_COMMAND:
            shell_env = _reset(child()) if program == "su" else child()
            for i, arg in enumerate(raw[1:], 1):
                # the string after -c, and for a shell any argument with spaces in it: a script
                # given as a here-document arrives that way. A shell of its own: what it sets stays there.
                if re.fullmatch(r"-\w*c", raw[i - 1]) or (program in _SHELLS and re.search(r"\s", arg)):
                    nest(arg, shell_env)
        elif program == "eval":
            return nest(" ".join(raw[1:]), scope)
        elif program == "find":
            for i, arg in enumerate(argv):
                if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                    rest = argv[i + 1:]
                    end = next((j for j, a in enumerate(rest) if a in (";", "+", "\\;")), len(rest))
                    if rest[:end]:
                        _program(rest[:end], False, scope, child)
        return None

    while i < len(toks):
        token = toks[i]
        i += 1
        ctx.work += 1
        if ctx.work > _WORK:
            raise ValueError("more to read than can be read")
        if defining is not None and not ((token.op and token in (";", "(")) or (token.plain and token in _BODIES)):
            raise ValueError("a function whose body cannot be read")
        if token.op and token in _LIST_OPS:
            operator(token)
            continue
        f = frames[-1]
        if f.case == "pattern":
            substitutions(token, env_in(f))
            if token == "esac" and token.plain:
                close("case")
            continue  # a pattern is matched against, not run
        if f.case == "head" and token == "in" and token.plain:
            f.words.append(token)
            finish(f, ";")
            f.case = "pattern"
        elif not f.words and token.plain and token == "function" and i < len(toks):
            defining, i = toks[i], i + 1  # function NAME [()] BODY
            if toks[i:i + 2] == ["(", ")"] and toks[i].op:
                i += 2
        elif not f.words and token.plain and token == "coproc":  # coproc [NAME] COMMAND, in the background
            if len(toks) > i + 1 and not toks[i].op and toks[i + 1] in ("{", "(") and (toks[i + 1].plain or toks[i + 1].op):
                i += 1
        elif not f.words and token.plain and token == "time":
            if toks[i:i + 1] == ["-p"]:  # bash's own: `time p=x` sets p, as `p=x` does
                i += 1
        elif not f.words and token.plain and (token in _KEYWORDS or token in _HEADS):
            finish(f, ";")  # what was closed before it: `{ a; } then`
            if token == "done" and frames[-1].kind == "loop" and again(frames[-1]):
                continue
            if token in _CLOSES:
                close(_CLOSES[token])
            else:
                if token in _OPENS:
                    snapshot = _snapshot(out)
                    open_(_OPENS[token])
                    if _OPENS[token] == "loop":
                        loop = frames[-1]
                        loop.at, loop.snapshot, loop.defined = i - 1, snapshot, ctx.defined
                        if carry and carry[0] == loop.at:
                            loop.start = loop.env = loop.entry = _union(loop.start, carry[1])
                            carry = None
                if token in _HEADS:
                    frames[-1].words.append(token)
                    frames[-1].head = True
                if token == "case":
                    frames[-1].case = "head"
        elif token.op and token in ("<(", ">("):  # the program is given a file that the commands in it write or read
            f.words.append(_token("/dev/fd/63", "/dev/fd/63", plain=True))
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
