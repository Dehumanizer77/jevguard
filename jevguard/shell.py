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
import time

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
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.S)
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
# \0 is a $ quoted against expansion (_LITERAL): text, which a shell may expand later (_wider)
_LITERAL_VAR = re.compile(r"\0(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_SINGLE_QUOTED = re.compile(r"'[^']*'")
# Which files these read is decided when they run: substitution, xargs, find, eval, sourced files.
_DYNAMIC = re.compile(r"\$\(|`|<\(|(?:^|[\s;|&(])(?:xargs|eval|source|find)\s|(?:^|[;|&(])\s*\.\s+\S")
# A file path inside a longer string (code passed to python -c, a quoted script).
_EMBEDDED = re.compile(r"(?<![\w./~-])(?:~|\.{1,2})?(?:/[\w.+@%-]+)+|(?<![\w./~-])[\w.+@%-]+(?:/[\w.+@%-]+)+")
_GLOB = re.compile(r"[*?\[]")


def canonical(path: str, base: str = "") -> str:
    """Absolute path with ~, relative parts and symbolic links resolved."""
    path = os.path.expanduser(path.replace("\0", "").replace("\x02", "").strip())
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
        # and what an argument that is a set of characters would name (tr's first, _set_operand):
        # kept apart, and named with the others only if the command may make a tr of its own
        self.program_sets: list[tuple[set[str], list[str]]] = []
        self.program_closed: list[bool] = []  # it writes no file and runs nothing this does not read (_only_reads)
        # the home and the directories above it that a script it runs as commands names: they count
        # for it only where they may reach something it does not read (_closed)
        self.program_carried: list[set[str]] = []
        self.assigned: list[str] = []        # the names of the variables it sets, in turn
        self.piping = False                  # a program in it is given its input through a pipe
        # the characters that read, or the splitting of a value not known, may end a word at
        # (IFS, read -d x, a line break): words of its texts cut there are paths it names (_pieces)
        self.breaks: set[str] = set()
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


def _prepare(cmd: str, code: bool = True) -> str:
    """cmd as the shell has it when it splits it into words. It is read as the shell reads it,
    quotes first, so that nothing in quotes or a comment is taken for any of this:

    - A backslash at the end of a line joins the next line to it, in the middle of a word too:
      `p\\` and `=x` on the next line are the assignment p=x (#65). Not in single quotes, $'...',
      a comment, or the text of a here-document whose marker is quoted.
    - `...` becomes the $(...) it stands for. In it a backslash quotes only $ ` \\ (and " in
      double quotes), and what is left is read as commands: `echo \\`rm x\\`` runs rm. `((...))`
      becomes `: $((...))`, and $[...] $((...)): arithmetic, which may give variables values.
    - A here-document becomes a here-string, `<<< TEXT`. Read line by line as commands, the first
      word of each line would be taken for a program and the paths it names would be lost. It
      stays a redirection, so that `p=x <<EOF` is still an assignment (#57). With a quoted marker
      TEXT is the text as written. With an unquoted one the shell expands $p, ${...}, $(...) and
      `...` in it before the program reads it, so those stay live in TEXT, for _walk to fill in
      where it reads the redirection: `bash <<EOF` hands bash what p holds here, and an
      assignment in the text cannot change that (#63).

    Only a `<<` outside quotes, comments, ${...} and arithmetic begins a here-document (code:
    cmd is commands, not the inside of an expansion). `<<<x`, '<<x', # <<x and $(( 1 <<x )) do
    not, and so do not take the lines after them for text. A here-document whose marker cannot
    be read, or that no line ends, raises ValueError: where its text ends cannot be told."""
    out: list[str] = []
    pending: list[tuple[int, bool, str, bool]] = []  # here-documents whose text begins on the next line
    i, word_start = 0, True
    while i < len(cmd):
        ch = cmd[i]
        if cmd.startswith("\\\n", i):
            i += 2
            continue
        if ch == "\\":
            out.append(cmd[i:i + 2])
            word_start, i = False, i + 2
            continue
        if ch == "'" or cmd.startswith("$'", i):
            end = cmd.find("'", i + 1) if ch == "'" else _escaped_end(cmd, i + 2, "'")
            if end < 0:  # the shell runs nothing from here; _tokens splits it all the same
                out.append(cmd[i:])
                break
            out.append(cmd[i:end + 1])
            word_start, i = False, end + 1
            continue
        if code and ch == "#" and word_start:
            end = cmd.find("\n", i)
            end = len(cmd) if end < 0 else end
            out.append(cmd[i:end])
            i = end
            continue
        if code and word_start and cmd.startswith("((", i) and _arithmetic_end(cmd, i + 2) >= 0:
            end = _arithmetic_end(cmd, i + 2)
            text, end = f": $(({_prepare(cmd[i + 2:end - 1], False)}))", end
        else:
            text, end = _expansion(cmd, i, "") if ch in "\"`$" else (None, i)
        if text is not None:
            if pending and "\n" in cmd[i:end + 1]:
                raise ValueError("a here-document whose text cannot be told")
            out.append(text)
            word_start, i = False, end + 1
            continue
        if code and cmd.startswith("<<<", i):
            out.append("<<<")
            word_start, i = True, i + 3
            continue
        if code and cmd.startswith("<<", i):
            strip = cmd.startswith("<<-", i)
            marker, quoted, i = _marker(cmd, i + 2 + strip)
            pending.append((len(out), strip, marker, quoted))
            out.append("")
            word_start = False
            continue
        out.append(ch)
        word_start, i = ch in _WORD_BREAKS, i + 1
        if ch == "\n" and pending:
            for at, strip, marker, quoted in pending:
                text, i = _heredoc(cmd, i, strip, marker, quoted)
                out[at] = f" <<< {shlex.quote(text) if quoted else _expanded(text)} "
            pending = []
    if pending:  # the line ends where the command does: no line can end the text
        raise ValueError("a here-document that no line ends")
    return "".join(out)


def _expansion(text: str, i: int, context: str) -> tuple[str | None, int]:
    """The quoted string, substitution or expansion that begins at i, prepared as _prepare
    prepares a command line, and where it ends; (None, i) if none begins there. context is
    where it stands: "" outside quotes, '"' in double quotes, "<<" in the text of a
    here-document, where " is a character."""
    if text[i] == '"' and not context:
        out, j = ['"'], i + 1
        while j < len(text):
            if text.startswith("\\\n", j):
                j += 2
                continue
            if text[j] == "\\":
                out.append(text[j:j + 2])
                j += 2
                continue
            if text[j] == '"':
                return "".join(out) + '"', j
            inner, end = _expansion(text, j, '"') if text[j] in "`$" else (None, j)
            out.append(text[j] if inner is None else inner)
            j = end + 1
        return text[i:], len(text) - 1  # a quote that does not end: as it is
    if text[i] == "`":
        end = _escaped_end(text, i + 1, "`")
        if end < 0:
            raise ValueError("a command substitution that does not end")
        escaped = "$`\\\n" + ('"' if context == '"' else "")
        inner = re.sub(r"\\(.)", lambda m: m.group(0) if m.group(1) not in escaped else
                       "" if m.group(1) == "\n" else m.group(1), text[i + 1:end], flags=re.S)
        return f"$({_prepare(inner)})", end
    if text.startswith("$(", i):
        end = _substitution_end(text, i + 2)
        if end < 0:
            raise ValueError("a command substitution that does not end")
        if text.startswith("$((", i) and _arithmetic_end(text, i + 3) == end:
            return f"$(({_prepare(text[i + 3:end - 1], False)}))", end
        return f"$({_prepare(text[i + 2:end])})", end
    if text.startswith("${", i):
        end = _brace_end(text, i + 2, bool(context))
        if end < 0:
            raise ValueError("an expansion that does not end")
        return f"${{{_prepare(text[i + 2:end], False)}}}", end
    if text.startswith("$[", i):  # old arithmetic
        depth = 0
        for j in range(i + 2, len(text)):
            depth += {"[": 1, "]": -1}.get(text[j], 0)
            if depth < 0:
                return f"$(({_prepare(text[i + 2:j], False)}))", j
    return None, i


def _marker(cmd: str, i: int) -> tuple[str, bool, int]:
    """The marker of a here-document from i, just after its `<<` or `<<-`: the line that ends its
    text, whether any of the marker is quoted (then nothing in the text is expanded), and where
    the marker ends."""
    while i < len(cmd) and (cmd[i] in " \t" or cmd.startswith("\\\n", i)):
        i += 2 if cmd[i] == "\\" else 1
    end = _word_end(cmd, i)
    raw = re.sub(r"\\(.)", lambda m: "" if m.group(1) == "\n" else m.group(0), cmd[i:max(end, i)], flags=re.S)
    if end <= i or re.search(r"\$[('\"]|`", raw):
        raise ValueError("a here-document whose marker cannot be read")
    return _unquote(raw).replace(_LITERAL, "$"), bool(re.search(r"[\\'\"]", raw)), end


def _heredoc(cmd: str, i: int, strip: bool, marker: str, quoted: bool) -> tuple[str, int]:
    """The text of a here-document whose lines begin at i, and where what follows it begins. The
    line that ends it is the marker, after <<- has taken the tabs off its start. With an unquoted
    marker a backslash at the end of a line joins the next line to it first."""
    lines = []
    while i < len(cmd):
        end = cmd.find("\n", i)
        end = len(cmd) if end < 0 else end
        line = cmd[i:end]
        while not quoted and (len(line) - len(line.rstrip("\\"))) % 2 and end < len(cmd):
            more = cmd.find("\n", end + 1)
            more = len(cmd) if more < 0 else more
            line, end = line[:-1] + cmd[end + 1:more], more
        if strip:
            line = line.lstrip("\t")
        if line == marker:
            return "\n".join(lines), end + 1
        lines.append(line)
        i = end + 1
    raise ValueError("a here-document that no line ends")


_PARAMETER = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])")


def _expanded(text: str) -> str:
    """The text of a here-document whose marker is not quoted, as one word: what the shell
    expands in it ($p, ${...}, $(...), `...`) in double quotes, and the rest, where a backslash
    quotes only $ ` and \\, in single quotes."""
    out, plain, i = [], [], 0
    while i < len(text):
        if text[i] == "\\" and text[i + 1:i + 2] in ("$", "`", "\\"):
            plain.append(text[i + 1])
            i += 2
            continue
        live, end = _expansion(text, i, "<<") if text[i] in "`$" else (None, i)
        parameter = _PARAMETER.match(text, i) if live is None else None
        if parameter:
            live, end = parameter.group(0), parameter.end() - 1
        if live is None:
            plain.append(text[i])
            i += 1
            continue
        out.append(f"{shlex.quote(''.join(plain)) if plain else ''}\"{live}\"")
        plain, i = [], end + 1
    if plain or not out:
        out.append(shlex.quote("".join(plain)))
    return "".join(out)


# A $ the shell takes as it is, in single quotes ('$1' in awk, $8924 in a quoted here-document).
# It stands in the words until a program's arguments are known, and is then a $ again.
_LITERAL = "\0"
# Marks where the output of a command substitution goes: $\x01<n>\x01 for the nth of a command.
_MARK = "\x01"
_RUN = re.compile(_MARK + r"(\d+)" + _MARK)
# Stands after a $ whose value is not known (a variable, the output of a command): a shell that
# reads the text later, in eval or `bash -c "..."`, is not to fill it in with its own (#63).
_OPAQUE = "\x02"
_WORD_BREAKS = set(" \t\n;&|()<>")
_OPERATORS = (";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|")
# Words after which the next one is again in the place of a command.
_BEFORE_COMMAND = {"if", "then", "else", "elif", "while", "until", "do", "!", "{", "time"}


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


def _brace_end(cmd: str, i: int, quoted: bool = False) -> int:
    """Where the `}` that closes a `${` is: `${x:-)}` holds a `)` that closes nothing. In double
    quotes and a here-document (quoted) a ' in it is a character."""
    while i < len(cmd):
        ch = cmd[i]
        if ch == "\\":
            i += 1
        elif ch == "'" and not quoted:
            i = cmd.find("'", i + 1)
        elif ch == '"':
            i = _double_quote_end(cmd, i + 1)
        elif ch == "`":
            i = _escaped_end(cmd, i + 1, "`")
        elif cmd.startswith("$(", i):
            i = _substitution_end(cmd, i + 2)
        elif cmd.startswith("${", i):
            i = _brace_end(cmd, i + 2, quoted)
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
    pattern (#52). The text of a here-document in it is stepped over, from the line after its
    marker to the line that ends it (_heredoc). A `)` closes the `$(` only when nothing opened in
    it is still open; one that fits nothing here gives -1, and so does a here-document whose end
    cannot be told: the caller does not guess where the command ends."""
    if cmd.startswith("(", i):  # `$((`: arithmetic, where `<<` is a shift, when `))` closes it
        end = _arithmetic_end(cmd, i + 1)
        if end >= 0:
            return end
    open_: list[str] = []  # "(", "case" before its `in`, "pattern" and "arm" after it
    command = True  # the next word is the first of a command, where `case` and `esac` are the shell's
    pending: list[tuple[bool, str, bool]] = []  # here-documents whose text begins on the next line
    while i < len(cmd):
        ch = cmd[i]
        if ch in " \t":
            i += 1
        elif cmd.startswith("\\\n", i):  # the line goes on: what follows starts a word as here
            i += 2
        elif ch == "\n":
            command, i = True, i + 1
            try:
                for strip, marker, quoted in pending:
                    i = _heredoc(cmd, i, strip, marker, quoted)[1]
            except ValueError:
                return -1
            pending = []
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
                strip = cmd.startswith("<<-", i)
                try:
                    marker, quoted, i = _marker(cmd, i + 2 + strip)
                except ValueError:
                    return -1
                pending.append((strip, marker, quoted))
                command = False
                continue
            i += 1
            while i < len(cmd) and cmd[i] in "<>&|" and cmd[i - 1] in "<>":
                i += 1
        elif ch == "(":
            if not (open_ and open_[-1] == "pattern"):  # `(a)`: a pattern may open with one
                open_.append("(")
            command, i = True, i + 1
        elif ch == ")":
            if not open_:
                return -1 if pending else i
            if open_[-1] == "(":
                open_.pop()
            elif open_[-1] == "pattern":
                open_[-1] = "arm"
            else:
                return -1
            command, i = True, i + 1
        else:
            start, i = i, _word_end(cmd, i)
            if i < 0 or (pending and "\n" in cmd[start:i]):
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
            out.append(shlex.quote(_ansi_c(cmd[i + 2:end])).replace("$", _LITERAL))
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
            arithmetic = cmd.startswith("$((", i) and _arithmetic_end(cmd, i + 3) == end
            runs.append(_Arithmetic(cmd[start:end]) if arithmetic else cmd[start:end])
            word_start, i = False, end + 1
            continue
        if ch == '"':
            quoted = not quoted
        out.append(ch)
        word_start, i = ch in _WORD_BREAKS, i + 1
    out.append(cmd[i:])  # after a single quote that is not closed: as it was, for tokens() to split
    return "".join(out), runs


class _Arithmetic(str):
    """The text of a $((...)) as _lift_substitutions lifts it, its brackets included: arithmetic,
    which may give variables values in this shell (_arithmetic)."""


_ANSI_C = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
           "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(text: str) -> str:
    """What $'...' stands for: \\n, \\x2e, \\056, \\u002e, \\cA and the rest as bash reads them.
    `$'\\x2eclaude'` is .claude. The string ends at a NUL, as it does for a program."""
    def one(m: re.Match) -> str:
        s = m.group(1)
        if s[0] in "01234567":
            return chr(int(s, 8) & 0xFF)
        if s[0] in "xuU" and len(s) > 1:
            return chr(int(s[1:], 16))
        if s[0] == "c" and len(s) > 1:
            return chr(ord(s[1]) & 0x1F)
        return _ANSI_C.get(s, "\\" + s)
    text = re.sub(r"\\([0-7]{1,3}|x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|c.|.)", one, text, flags=re.S)
    return text.split("\0", 1)[0].replace(_MARK, "").replace(_OPAQUE, "")


# Every operator, longest first. A run of ; & | ( ) < > is split into these as the shell splits it:
# `a;>f` is a, ;, >, f, and in `(a)>f` the bracket closes before f is written.
_SHELL_OPS = sorted({"&&", "||", ";;&", ";;", ";&", "|&", ";", "&", "|", "(", ")", "<(", ">(", "<<<", "<<-", "<<",
                     "<>", "<&", ">&", ">>", ">|", "&>>", "&>", "<", ">"}, key=len, reverse=True)
# Those that join or end commands. The others are redirections, and part of the command they are in.
_LIST_OPS = {"&&", "||", ";;&", ";;", ";&", "|&", ";", "&", "|", "(", ")"}
_FD = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*\}")              # 2>, {fd}>: the descriptor a redirection is for
_REDIRECTION = re.compile(r"[<>&]*[<>][<>&|]*")
_ARRAY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")                 # NAME=( ... ), NAME+=( ... )
# An assignment as written: its name, any [index] and the = outside quotes. `'p=x'` and `p\=x` are programs.
_ASSIGN_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_ASSIGN_PARTS = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?(\+?)=(.*)", re.S)


class _Token(str):
    """A word or an operator of a command line, and how it was written. The shell takes `done`
    for the end of a loop and `'done'` for a program, `p=x` for an assignment and `'p=x'` or
    `p\\=x` for a program, `>` for a redirection and `'>'` for an argument."""
    op = False     # an operator or a redirection, outside quotes
    fd = False     # the 2 of `2>`, the {fd} of `{fd}>`: part of the redirection after it
    plain = False  # nothing in it is quoted or escaped: if it is a reserved word, it is one
    raw = ""       # as written; empty where that cannot be told
    array = None   # NAME=( ... ): the words in the brackets
    bare: frozenset = frozenset()  # where in it a $ stands outside quotes: what it expands to is split (_fields)
    muddled = False  # a quote or a backslash inside a ${...}: _unquote has taken away what it quoted there


def _token(text: str, raw: str, **how) -> _Token:
    token = _Token(text)
    token.raw = raw
    token.__dict__.update(how)
    return token


def _unquote(raw: str, bare: list[int] | None = None) -> str:
    """A word as the shell has it once its quotes are taken away. A $ that was quoted or escaped
    against expansion is _LITERAL: `\\$p` and `"\\$p"` are the text $p, as '$p' is. bare: where
    in the result a $ stands that was in no quotes, whose expansion the shell splits (#74)."""
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
                    i = _unquoted_char(raw, i, out)
            i += 1
        else:
            if ch == "$" and bare is not None:
                bare.append(sum(map(len, out)))
            i = _unquoted_char(raw, i, out)
    return "".join(out)


def _unquoted_char(raw: str, i: int, out: list[str]) -> int:
    """The character at i, put on out, and where the next one is. A $NAME that a quote or a
    backslash ends, and that a character of a name follows once they are gone, is put as ${NAME}:
    else `"$p"de` and `$p''de` would be $pde, a variable of another name (#74)."""
    name = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)['\"\\]+[A-Za-z0-9_]", raw[i:])
    if name:
        name = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", raw[i:])
        out.append("${" + name.group(1) + "}")
        return i + name.end()
    out.append(raw[i])
    return i + 1


def _bare_token(raw: str, **how) -> _Token:
    """A word as _unquote has it, with where its $ outside quotes are (_Token.bare)."""
    bare: list[int] = []
    return _token(_unquote(raw, bare), raw, bare=frozenset(bare),
                  muddled=bool(re.search(r"\$\{[^}]*[\\'\"]", raw)), **how)


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
            words.append(_bare_token(text[i:end]))
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
                out.append(_bare_token(raw, plain=not re.search(r"[\\'\"]", raw)))
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
_SETS = {"read", "mapfile", "readarray", "getopts", "printf", "wait", "unset"}
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
    it is written. $_ is the last word of the command before, which this does not keep: it is
    not what it was where the guard was started, nor what the command assigned to it."""
    if name == "_":
        return (None,)
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
    return _unknown(env)


def _unknown(env: dict) -> dict:
    """What the variables may hold after something runs in this shell that may set any of them
    to anything, and that this cannot follow: a builtin whose name is made at run time, a
    sourced file, arithmetic on a value that is not known. Each may still hold what it held, or
    a value that is not known; functions too. IFS as well, though neither set it: what the shell
    splits words at is then not known (_fields)."""
    return {name: _merge(_values(env, name), (None,)) for name in {*env, *os.environ, "IFS"}}


def _cleared(env: dict) -> dict:
    """`env -i`: nothing set but what env sets after it."""
    return {name: (None,) for name in {*env, *os.environ}}


# $NAME, ${NAME}, and ${NAME} with an operator after the name: ${p:-x}, ${p%/*}, ${p//a/b}, ${p:1:2},
# and a ${...} in the word after it: ${p:=${q:-x}}. A subscript, ${a[@]}, stands for each value.
_EXPANSION = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]{}]*\])?\}|([A-Za-z_][A-Za-z0-9_]*)"
                        r"|\{([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]{}]*\])?"
                        r"(:?[-=+?]|##?|%%?|/[/#%]?|\^\^?|,,?|:)((?:[^{}]|\$\{[^{}]*\})*)\})")


_LEFT = re.compile(r"\$(?=\{|[0-9@*#?$!-])")

# Not set: beside None, which stands for not set or not known, where the two read differently.
_UNSET = object()


_ARITHMETIC_SETS = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?(?:<<|>>|[-+*/%&^|])?=(?!=)"
                              r"|(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)?(?:\+\+|--)")
_NUMBER = re.compile(r"\s*[-+]?\d*\s*")


def _arithmetic(text: str, env: dict) -> dict:
    """What the variables hold once text is read as arithmetic: in $((...)), ((...)), let, the
    operands of [[ -eq ]], a subscript, an offset. A variable given a value there (`p = 1`,
    `p += 2`, `p++`) holds a number this does not work out. The value of a variable named in it
    is read as arithmetic in turn, so `n='p=1'; : $((n))` sets p: where one may hold anything but
    a number, or what it holds is not known, or a $ gives what this cannot see, any variable may
    have changed."""
    assigned = set()
    for reading, in _readings([text], env):
        if re.search(r"[$`\x00]", reading):
            return _unknown(env)
        names = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", re.sub(r"\b\d[\w#@]*", "", reading)))
        if any(v is None or not _NUMBER.fullmatch(v) for name in names for v in _values(env, name)):
            return _unknown(env)
        assigned |= {a or b or c for a, b, c in _ARITHMETIC_SETS.findall(reading)}
    return {**env, **{name: _merge(_values(env, name), (None,)) for name in assigned}} if assigned else env


def _assigned(word: str, env: dict, runs: list[str]) -> dict:
    """What the variables hold once the word is expanded (#64). ${p:=x} and ${p=x} give p the
    value x where it is not set (or null); ${!p:=x} gives it to the variable p names, which may be
    any. $((...)), and a subscript or an offset in ${...}, are arithmetic (_arithmetic). A value
    is added to those the variable held: whether that part of the word is expanded, and what it
    holds just then, is not followed. A value with quotes or braces in it this cannot tell, as
    the word comes with its quotes taken away: the variable may then hold anything."""
    for n in _RUN.findall(word):
        if isinstance(runs[int(n)], _Arithmetic):
            env = _arithmetic(runs[int(n)], env)
    i = word.find("${")
    while i >= 0:
        depth, end = 0, i + 2
        while end < len(word) and (depth or word[end] != "}"):
            depth += 1 if word.startswith("${", end) else -1 if word[end] == "}" else 0
            end += 1
        m = re.fullmatch(r"(!?)([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?(.*)", word[i + 2:end], re.S)
        if m:
            bang, name, index, rest = m.groups()
            if index and index not in ("@", "*"):
                env = _arithmetic(index, env)
            if re.match(r":[^-=+?]", rest):  # ${p:offset} and ${p:offset:length}
                env = _arithmetic(rest[1:].replace(":", ","), env)
            given = re.match(r":?=(.*)", rest, re.S)
            if given and bang:
                return _unknown(env)
            if given:
                values = tuple(r[0] for r in _readings([given.group(1)], env, split=False))
                if re.search(r"['\"\\{}" + _LITERAL + "]", re.sub(r"\$\{[^{}]*\}", "", given.group(1))):
                    values += (None,)
                env = {**env, name: _merge(_values(env, name), values)}
        i = word.find("${", i + 2)
    return env


def _builtin(argv: list[str]) -> list[str]:
    """The command as the shell runs it: without the `builtin` and `command` in front, after which
    a builtin still runs in this shell, read and printf -v and unset too (#62). `command -v` and
    `-V` only say what a name is: [] then."""
    while len(argv) > 1 and argv[0] in ("builtin", "command"):
        k = 1
        while k < len(argv) and argv[k].startswith("-") and len(argv[k]) > 1:
            k += 1
            if argv[k - 1] == "--":
                break
            if argv[0] == "command" and set(argv[k - 1]) & {"v", "V"}:
                return []
        argv = argv[k:]
    return argv


def _param(value: str | None, op: str, arg, ampersand: bool = True) -> str | None:
    """What ${NAME<op><arg>} gives for a NAME that holds value (None: not set); for ${p/x/y} arg is
    (x, y), each with the variables in it put in. None where the result is what NAME or arg holds
    and that is not known: the word then stays as it is written, and counts as fed from
    elsewhere. Where the result is a part or a change of a known value, which the command names
    nowhere else, only bash's own result will do (#75, #81-#83). This works it out for the forms
    whose result is plain, as checked against bash: a prefix or suffix taken off by a pattern of
    *, ? and other characters; a replacement of text without any of those; a case change of all
    or the first character; an offset and a length in decimals. For any other the command cannot
    be read. All only on ASCII text, past which bash's offsets and case changes depend on the
    locale. ampersand: a & in the replacement is the text that matched, as bash 5.2 has it with
    patsub_replacement on, its default; else a &."""
    unset = value is None
    null = unset or value == ""
    if op in ("-", "=", ":-", ":=", "+", ":+"):
        given = unset if op in ("-", "=", "+") else null
        if op[-1] in "-=" and not given:
            return value
        if op[-1] == "+" and given:
            return ""
        return None if re.search(_UNREAD, arg) else arg
    if unset or op in ("?", ":?") or _OPAQUE in value:
        return None if unset or _OPAQUE in value else value
    words = arg if isinstance(arg, tuple) else (arg,)
    if not value.isascii() or any(re.search(_UNREAD, w) or not w.isascii() for w in words):
        raise ValueError("a ${...} whose result cannot be told")
    if op in ("#", "##", "%", "%%"):  # the shortest or longest start or end that matches, taken off
        rx = _pattern(arg)
        if op[0] == "#":
            ks = range(len(value) + 1) if op == "#" else range(len(value), -1, -1)
            return next((value[k:] for k in ks if re.fullmatch(rx, value[:k], re.S)), value)
        ks = range(len(value), -1, -1) if op == "%" else range(len(value) + 1)
        return next((value[:k] for k in ks if re.fullmatch(rx, value[k:], re.S)), value)
    if op[0] == "/":  # text without *, ? or [: where it first stands, at the start, at the end, or each
        pattern, put = arg
        if re.search(r"[*?\[]", pattern):
            raise ValueError("a ${.../.../...} pattern whose matches this does not work out")
        put = put.replace("&", pattern) if ampersand else put
        if op == "/#":
            return put + value[len(pattern):] if value.startswith(pattern) else value
        if op == "/%":
            return value[:len(value) - len(pattern)] + put if value.endswith(pattern) else value
        if not pattern:
            return value
        return value.replace(pattern, put, -1 if op == "//" else 1)
    if op in ("^", "^^", ",", ",,"):
        if arg:
            raise ValueError("a ${...} case change of the characters a pattern matches")
        case = str.upper if op[0] == "^" else str.lower
        return case(value) if len(op) == 2 else case(value[:1]) + value[1:]
    if op == ":":  # ${p:offset} and ${p:offset:length}, as decimals: 010 is eight to bash (#83)
        number = r"\s*(?:\(\s*)?(-?(?:0|[1-9]\d*))\s*(?:\)\s*)?"
        m = re.fullmatch(number + r"(?::" + number + r")?", arg)
        if not m:
            raise ValueError("a ${...} offset that is not a decimal")
        start = int(m.group(1))
        if start < 0:
            start += len(value)
            if start < 0:  # further back than the start: nothing
                return ""
        if m.group(2) is None:
            return value[start:]
        length = int(m.group(2))
        end = start + length if length >= 0 else len(value) + length
        if end < start:  # bash: substring expression < 0, and nothing after it runs
            raise ValueError("a ${...} length bash refuses")
        return value[start:end]
    raise ValueError("a ${...} whose result cannot be told")


# What the word of a ${p<op>word} holds that this cannot read: a $ not put in, a quote, a
# backslash, a command's output.
_UNREAD = r"[$`\\'\"" + _LITERAL + _MARK + _OPAQUE + "]"


def _pattern(pattern: str) -> str:
    """bash's pattern of *, ? and other characters as a regular expression. A [...] and an
    extended glob (@(...) and the like, which shopt extglob turns on) the command cannot be read
    with."""
    if re.search(r"\[|[?*+@!]\(", pattern):
        raise ValueError("a pattern with a [...] or what may be an extended glob")
    return "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)


# ${a[@]}, ${a[*]}, ${!a[@]}, and the arguments: $@, $*, ${@...}, ${*...}
_ELEMENTS = re.compile(r"\$\{!?([A-Za-z_][A-Za-z0-9_]*)\[([@*])\]|\$\{?([@*])")


def _elements(word: str, env: dict, bare: frozenset, apart: bool) -> None:
    """Raises where the elements of an array or the arguments are put in in a way this does not
    read (#86). In a word that is one of a command's (apart), "${a[@]}" and ${a[*]} make each
    element a word of its own: _readings reads each value a may hold, which is right where the
    expansion is the whole word. Beside other text only the first and the last element take it
    (`a=(x .claude); touch "y${a[@]}"` touches yx and .claude). Quoted ${a[*]}, and any of them
    where the shell makes no words (an assignment, [[ ]], case, a redirection), is one word: the
    elements joined at the first character of IFS, which makes a path of pieces that each name
    nothing (`IFS=; a=(.cl aude); touch "${a[*]}"` touches .claude). That this reads only where IFS
    begins with a space, a tab or a newline: two elements joined then hold one, and no path does.
    For the arguments and an array that is not known it holds as well: what they are joined at
    is not named anywhere in the command."""
    for m in _ELEMENTS.finditer(word):
        joined = not apart or ("*" in (m.group(2) or m.group(3)) and m.start() not in bare)
        if joined:
            if not all(ifs is not None and ifs[:1] in (" ", "\t", "\n") for ifs in _ifs(env)):
                raise ValueError("elements joined at a character that is not a space (IFS)")
            continue
        known = m.group(1) and not word.startswith("${!", m.start()) and \
            any(v is not None and _OPAQUE not in v for v in _values(env, m.group(1)))
        whole = _EXPANSION.match(word, m.start())
        if known and not (m.start() == 0 and whole and whole.end() == len(word)):
            raise ValueError("the elements of an array put in beside other text")


def _readings(words: list[str], env: dict, envs: list[dict] | None = None, split: bool = True,
              breaks: set[str] | None = None) -> list[list[str]]:
    """The words with the values of their variables put in, once for each combination of the
    values they may hold; envs gives each word an env of its own. Past _READINGS what the command
    is given cannot be told. A $ in single quotes (_LITERAL) is not filled in: it is text, and a
    shell that reads it later, in `bash -c` or eval, has variables of its own then (#58).

    A value that is not known stays as it is written, with _OPAQUE after its $, and so does the
    output of a command: the word is fed from elsewhere, and a shell that reads it later does not
    take it for its own variable (#63). Such a word is fed whatever the others hold, so a variable
    that may hold one is read so once, beside the combinations of the values that are known.

    A known value put in where the $ was in no quotes is split at the characters of IFS, as the
    shell splits it (_fields, #74): `p='.claude notes'; rm -rf $p` removes .claude. Not where the
    shell does not split (split=False: case WORD, [[ ]], the value of an assignment), in the word
    of a redirection, nor in an assignment to export and the like. And where a replacement has a &
    in it, once as bash 5.2 reads it, the text the pattern matched, and once as older shells do
    (#75). The elements of an array, and the arguments, as _elements says (#86).

    breaks: where given, the characters of IFS where a word has something in no quotes the shell
    splits are added to it: a value not known is cut there (Command.breaks)."""
    envs = envs or [env] * len(words)
    declaring = bool(words) and str(words[0]) in _DECLARE
    splits = []
    for k, word in enumerate(words):
        before = words[k - 1] if k else ""
        apart = split and not (getattr(before, "op", False) and _REDIRECTION.fullmatch(before)) and \
            not (declaring and _ASSIGN_WORD.match(word))
        splits.append(getattr(word, "bare", frozenset()) if apart else frozenset())
        _elements(word, envs[k], splits[-1], apart)
        if breaks is not None and (splits[-1] or apart and _RUN.search(word)):
            breaks.update(ch for ifs in _ifs(envs[k]) for ch in ifs or "")
    held: dict[tuple, tuple] = {}
    for word, e, bare in zip(words, envs, splits):
        for m in _EXPANSION.finditer(word):
            name = m.group(1) or m.group(2) or m.group(3)
            key = (id(e), name)
            held.setdefault(key, _values(e, name))
            if m.group(4) and None in held[key] and _UNSET not in held[key]:
                held[key] += (_UNSET,)  # ${p:-x} on what may not be known: read as unknown, and as not set
            for inner in _EXPANSION.finditer(m.group(5) or ""):  # ${p#$q}, ${p:=${q:-x}}: q is expanded first
                name = inner.group(1) or inner.group(2) or inner.group(3)
                held.setdefault((id(e), name), _values(e, name))
                if inner.group(4) and None in held[(id(e), name)] and _UNSET not in held[(id(e), name)]:
                    held[(id(e), name)] += (_UNSET,)
            if m.start() in bare:
                held.setdefault((id(e), _IFS), _ifs(e))
    keys = list(held)
    known = [tuple(v for v in held[k] if v is not None) or (None,) for k in keys]
    patsub = (True, False) if any(m.group(4) and m.group(4)[0] == "/" and re.search(r"[&$]", m.group(5))
                                  for word in words for m in _EXPANSION.finditer(word)) else (True,)
    if math.prod(len(c) for c in known) * len(patsub) > _READINGS:
        raise ValueError("variables that may hold more values than can be read")
    combinations = list(itertools.product(*known))
    if any(None in held[k] and c[0] is not None for k, c in zip(keys, known)):
        combinations.append(tuple(None if None in held[k] else c[0] for k, c in zip(keys, known)))
        combinations.sort(key=lambda c: [held[k].index(v) for k, v in zip(keys, c)])  # as the values come
    readings = []
    for combination, ampersand in itertools.product(combinations, patsub):
        value = dict(zip(keys, combination))
        reading = []
        for word, e, bare in zip(words, envs, splits):
            def inner(text: str, e=e) -> str:  # the word of a ${p<op>word}, with what is in it put in, unsplit
                return _EXPANSION.sub(lambda m: put(m, e, frozenset()), text)

            def put(m: re.Match, e=e, bare=bare) -> str:
                v = value[(id(e), m.group(1) or m.group(2) or m.group(3))]
                if m.group(4):
                    if v is not None and v is not _UNSET and _OPAQUE not in v and getattr(word, "muddled", False) and \
                            m.group(4).lstrip(":") not in ("-", "=", "+", "?"):
                        raise ValueError("a ${...} whose pattern is quoted in a way this cannot see")
                    if m.group(4)[0] == "/":  # where the pattern ends is in the word as written (#81)
                        cut = re.match(r"(?:[^/$]|\$\{[^{}]*\}|\$(?!\{))*", m.group(5)).end()
                        arg = (inner(m.group(5)[:cut]), inner(m.group(5)[cut + 1:]))
                    else:
                        arg = inner(m.group(5))
                    if m.group(4) == ":" and "[" in m.group(0).partition(":")[0] and v is not None and v is not _UNSET:
                        raise ValueError("a slice of an array")  # ${a[@]:1} takes elements, not characters
                    v = None if v is None else _param(None if v is _UNSET else v, m.group(4), arg, ampersand)
                if v is None or v is _UNSET:
                    return "$" + _OPAQUE + m.group(0)[1:]
                return _FIELD + v + _FIELD_END if m.start() in bare else v
            # after _EXPANSION: `$` and what follows the mark is no name. What is left that the
            # shell expands here (${!p}, ${p@Q}, $1) is not known either.
            spans = [m.span() for m in _EXPANSION.finditer(word)]
            for left in re.finditer(r"\$\{!?([A-Za-z_][A-Za-z0-9_]*)", word):
                if any(a <= left.start() < b for a, b in spans):
                    continue  # one this reads, or a ${...} in its word
                if any(v is not None and _OPAQUE not in v for v in _values(e, left.group(1))):
                    # ${!p}, ${p@L}, ${p:-${q}} of a known value: what it gives is named nowhere else
                    raise ValueError("a ${...} of a known value that this does not work out")
            text = _LEFT.sub("$" + _OPAQUE, _RUN.sub(_OPAQUE, _EXPANSION.sub(put, word)))
            if _FIELD in text:
                reading.extend(_fields(text, value[(id(e), _IFS)], not getattr(word, "plain", True)))
            else:
                reading.append(text)
        readings.append(reading)
    return readings


# Around a value put in where its $ was in no quotes, until the word is split (_fields).
_FIELD, _FIELD_END = "\x03", "\x04"
_IFS = "\0IFS"  # the key under which _readings holds what IFS may be, beside the variable itself


def _ifs(env: dict) -> tuple:
    """What the shell may split words at: space, tab and newline where IFS is not set, and where
    it may be not known, None: also where part of it is (`IFS=$(...)`)."""
    if "IFS" not in env and "IFS" not in os.environ:
        return (" \t\n",)
    return tuple(dict.fromkeys(None if v is None or _OPAQUE in v else v for v in _values(env, "IFS")))


_NAME_CHAR = re.compile(r"[A-Za-z0-9._~/+@%-]")  # what _pieces takes for part of a file name
_HEX_ESCAPE = r"|x([0-9A-Fa-f]{1,2})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|(.))"
# A backslash escape as bash reads it in printf's format (\056), in a %b argument (\0056, \056)
# and in echo -e (\0056 only)
_ESCAPES = {"format": re.compile(r"\\(?:([0-7]{1,3})" + _HEX_ESCAPE, re.S),
            "%b": re.compile(r"\\(?:(0[0-7]{0,3}|[1-7][0-7]{0,2})" + _HEX_ESCAPE, re.S),
            "echo": re.compile(r"\\(?:(0[0-7]{0,3})" + _HEX_ESCAPE, re.S)}
_ESCAPED = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
            "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _unescape(text: str, escape: re.Pattern, cut: bool = False) -> str:
    """text with the backslash escapes of one of _ESCAPES turned into the characters they
    stand for. cut: up to the first \\c, after which %b and echo -e print nothing."""
    out, at = [], 0
    for m in escape.finditer(text):
        out.append(text[at:m.start()])
        at = m.end()
        octal, hexa, short, long, other = m.groups()
        if other == "c" and cut:
            return "".join(out)
        if other is not None:
            out.append(_ESCAPED.get(other, m.group()))
            continue
        try:
            out.append(chr(int(octal, 8) if octal is not None else int(hexa or short or long, 16)))
        except (ValueError, OverflowError):
            out.append(m.group())
    return "".join(out) + text[at:]


def _received(text: str) -> list[str]:
    """What a variable may be given of printed text: no shell value holds a NUL, so read and
    $(...) leave it out (`.cl\\0aude` is .claude); and read without -r takes a backslash off
    the character after it, and with a line break off both (`\\/` is /, #74)."""
    forms = [text, re.sub(r"\\(.)", lambda m: "" if m.group(1) == "\n" else m.group(1), text, flags=re.S)] \
        if "\\" in text else [text]
    return list(dict.fromkeys(f for form in forms for f in (form, form.replace("\0", ""))))


def _printed(text: str) -> list[str]:
    """What a variable may be given of a text the command prints (_received): the text, and
    where it has a backslash, what printf and echo -e print of it (\\n is a line break, \\056 a
    dot), also up to a \\c, where they stop (`printf %b '/\\cfoo'` prints /, #74)."""
    forms = [text] + [_unescape(text, e, cut) for e in _ESCAPES.values() for cut in (False, True)] \
        if "\\" in text else [text]
    return list(dict.fromkeys(f for form in dict.fromkeys(forms) for f in _received(form)))


_PRINTF = re.compile(r"(%%)|%([-+ #0]*)(\*|[0-9]*)(?:\.(\*|[0-9]*))?[hjlLtz]*(\([^)]*\))?(.?)"
                     r"|(\\(?:[0-7]{1,3}|x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|.)?)|([^%\\]+)", re.S)


def _printf(args: list[str]) -> list[str]:
    """What printf prints given args, as bash 5.2 prints it: its format with the escapes in it,
    each directive given the next argument, and the format again while arguments are left
    (`printf '%s%s\\n' .cl aude` prints .claude). %b reads escapes as echo -e does, and a \\c
    there ends all output; %c and a precision print part of an argument (`%.1s` of /x is /). A
    number that cannot be read is 0, a time is now, an invalid directive ends the output. Where
    the format has \\c, also what coreutils printf prints, which ends there."""
    while args[:1] and args[0].startswith("-v"):  # -v NAME: printed into a variable
        args = args[1 if len(args[0]) > 2 else 2:]
    args = args[args[:1] == ["--"]:]
    if not args:
        return []
    outs = []
    for stop in (False, True) if "\\c" in args[0] else (False,):
        out, left, size, done = [], list(args[1:]), 0, False

        def take() -> str:
            return left.pop(0) if left else ""
        while not done:
            before = len(left)
            for m in _PRINTF.finditer(args[0]):
                percent, flags, width, precision, when, conv, escape, text = m.groups()
                if percent or text is not None:
                    out.append(text or "%")
                    continue
                if escape is not None:
                    if escape == "\\c" and stop:
                        done = True
                        break
                    out.append(_unescape(escape, _ESCAPES["format"]))
                    continue
                if not conv or conv not in "sbqQcdiouxXeEfFgGaAT" or (when is not None) != (conv == "T"):
                    done = True  # bash: an invalid format character, and nothing more is printed
                    break
                w = _number(take(), False) if width == "*" else int(width or 0)
                p = (_number(take(), False) if precision == "*" else int(precision or 0)) \
                    if precision is not None else None
                flags += "-" * (w < 0)
                w, p = min(abs(w), 4096), None if p is None or p < 0 else min(p, 4096)
                if conv in "sqQc":
                    s = take()
                    s = s[:1] if conv == "c" else re.sub(r"([^A-Za-z0-9_./:@%+,=-])", r"\\\1", s) \
                        if conv in "qQ" else s
                elif conv == "b":
                    arg = take()
                    s = _unescape(arg, _ESCAPES["%b"], cut=True)
                    done = s != _unescape(arg, _ESCAPES["%b"])  # a \c: nothing more is printed
                elif conv == "T":
                    take()
                    try:
                        s = time.strftime(when[1:-1] or "%X")
                    except ValueError:
                        s = when[1:-1]
                else:
                    s = _number_text(flags, w, p, conv, _number(take(), conv in "eEfFgGaA"))
                if p is not None and conv in "sbqQT":
                    s = s[:p]
                if conv not in "diouxXeEfFgGaA":
                    s = s.ljust(w) if "-" in flags else s.rjust(w)
                out.append(s)
                size += len(s)
                if size > 100_000:
                    raise ValueError("printf prints more than can be read")
                if done:
                    break
            done = done or not left or len(left) == before
        outs.append("".join(out))
    return list(dict.fromkeys(outs))


def _number(arg: str, real: bool) -> int | float:
    """The number printf reads in arg: a character's code after a quote, an integer in C's
    bases (0x1f, 017), or a real number. 0 where it reads none."""
    s = arg.lstrip()
    if s[:1] in ("'", '"'):
        return ord(s[1]) if len(s) > 1 else 0
    m = re.match(r"[-+]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|inf|nan)", s, re.I) if real else \
        re.match(r"[-+]?(?:0[xX][0-9A-Fa-f]+|0[0-7]*|[1-9][0-9]*)", s)
    if not m:
        return 0.0 if real else 0
    if real:
        return float(m.group())
    digits = m.group().lstrip("+-")
    value = int(digits, 16) if digits[:2] in ("0x", "0X") else int(digits, 8) if digits[0] == "0" else int(digits)
    return -value if m.group().startswith("-") else value


def _number_text(flags: str, width: int, precision: int | None, conv: str, value: int | float) -> str:
    """value as printf's directive % flags width .precision conv prints it."""
    try:
        if conv in "aA":
            text = float(value).hex()
            return text.upper() if conv == "A" else text
        if conv in "ouxX" and value < 0:
            value += 1 << 64
        spec = "%" + flags + (str(width) if width else "") + ("." + str(precision) if precision is not None else "")
        text = (spec + {"i": "d", "u": "d"}.get(conv, conv)) % value
        return text.replace("0o", "0", 1) if conv == "o" else text
    except (TypeError, ValueError, OverflowError):
        return str(value)


def _pieces(text: str, breaks: set[str] | frozenset = frozenset(), forms: list[str] | None = None) -> list[str]:
    """The words text may be split into where what IFS holds is not known here: at spaces and at
    any character that is not part of a file name. Nothing where it has none of them. The same
    of each of forms, by default what a variable may be given where the text is printed
    (_printed); of what printf has printed, what a variable may be given of it (_received).

    breaks: characters the command may also split at (Command.breaks). There a word is cut too,
    and what follows each one is a word as well: read gives its last variable the rest of the
    line (`IFS=x read a b <<< notesx.claude` gives b .claude, #74).

    Only slashes are a word where the start or the end of the text or one of the breaks is on
    each side, past the spaces and tabs read takes off: that is the root a read or a split gives
    (`IFS=x read a b <<< notesx/`, `read a b <<< 'x /'`). Not elsewhere (`read a <<< 'x / y'`,
    `s|/|-|`): no read or split the command runs gives it there."""
    edge = "[" + "".join(re.escape(ch) for ch in sorted(breaks)) + "]" if breaks else None
    root = re.compile(rf"(?:\A|(?<={edge}))[ \t]*(/+)[ \t]*(?={edge}|\Z)" if edge else r"\A[ \t]*(/+)[ \t]*\Z")
    pieces, roots, count = [], [], 0
    for form in _printed(text) if forms is None else forms:
        for run in re.split(r"[^A-Za-z0-9._~/+@%-]+", form):
            pieces.append(run)
            cuts = [i for i, ch in enumerate(run) if ch in breaks]
            count += len(cuts)
            if count > 2000:
                raise ValueError("a text split at more places than can be read")
            if cuts:
                pieces += re.split(edge, run)
                pieces += [run[i + 1:] for i in cuts]
        roots += [m.group(1) for m in root.finditer(form)]
    pieces = list(dict.fromkeys([p for p in pieces if p.strip("/")] + roots))
    return [] if pieces == [text] else pieces


def _fields(text: str, ifs: str | None, quoted: bool) -> list[str]:
    """The words the shell makes of text by splitting what stands between _FIELD and _FIELD_END
    at the characters of ifs. A run of spaces, tabs and newlines in ifs is one break and makes no
    word at either end; any other character of ifs ends a word, an empty one too, and the spaces
    around it go with it. An empty ifs splits nothing. Nothing left is no word, unless part of it
    was quoted. Where ifs is not known (None), which words there are cannot be told."""
    if ifs is None:
        if re.search(_FIELD + "[^" + _FIELD_END + "]", text):
            raise ValueError("a value split at characters that are not known (IFS)")
        ifs = ""
    words: list[str] = []
    word: list[str] = []
    begun = after_space = inside = False
    for ch in text:
        if ch in (_FIELD, _FIELD_END):
            inside = ch == _FIELD
        elif inside and ch in ifs and ch in " \t\n":
            if begun:
                words.append("".join(word))
                word, begun, after_space = [], False, True
        elif inside and ch in ifs:
            if not after_space:
                words.append("".join(word))
            word, begun, after_space = [], False, False
        else:
            word.append(ch)
            begun, after_space = True, False
    if begun:
        words.append("".join(word))
    return words or ([""] if quoted else [])


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
    return len(out.programs), len(out.globs), len(out.dirs), set(out.paths), set(out.writes), len(out.assigned)


def _restore(out: Command, snapshot: tuple) -> None:
    """out as it was at the snapshot: what was read since is read again."""
    programs, globs, dirs, paths, writes, assigned = snapshot
    for each in (out.programs, out.program_dirs, out.program_paths, out.program_globs, out.program_fed,
                 out.program_sets, out.program_closed, out.program_carried):
        del each[programs:]
    del out.assigned[assigned:]
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
# Options of xargs that put its input in place of a string in the words after it ({} if none is given).
_WRAPPER_REPLACES = {("xargs", "I"), ("xargs", "i"), ("xargs", "--replace")}
_ENV_LONG = {"--ignore-environment": "i", "--null": "0", "--debug": "v", "--unset": "u", "--chdir": "C",
             "--split-string": "S", "--argv0": "a"}


_IMPORTS = "BASH_FUNC_"  # the names bash takes functions from in its environment: BASH_FUNC_name%%


def _known_entry(word: str, replaced: list[str]) -> None:
    """The name of an entry env or sudo puts in the environment of what it runs, or a word they may
    take for NAME=VALUE once it is filled in: "$a", a glob that matches a file named so, a word
    with what xargs -I puts its input in place of (replaced). One whose text is not known may be a
    function bash imports (#69), and so is one named BASH_FUNC_...: env -S joins its quoted pieces
    into such a name only after the words of the command were looked at (run)."""
    if not _as_written(word) or any(g in word for g in replaced):
        raise ValueError("an environment entry whose name is not known")
    if _IMPORTS in word:
        raise ValueError("an environment entry a shell takes for a function")


def _sudo_entry(wrapper: str, word: str) -> bool:
    """sudo takes a word with = in it, before its program, for NAME=VALUE, unless it begins with /."""
    return wrapper == "sudo" and "=" in word and not word.startswith(("-", "/"))


def _env(argv: list[str], child: dict, out: Command, replaced: list[str]) -> tuple[list[str], dict]:
    """env's options and NAME=VALUE operands: the program after them, and what it is run with
    (#59). The variables env sets, unsets (-u) or clears (-i) are the program's, not this shell's.
    An option this does not know may change what the program is or what it finds, and cannot be
    read. replaced: what an xargs before it puts its input in place of (_known_entry)."""
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
                _known_entry(word, replaced)  # the program, unless the shell or xargs makes NAME=VALUE of it
                argv.insert(0, word)
                break
            name, value = word.split("=", 1)
            _known_entry(name, replaced)
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
    replaced: list[str] = []  # what xargs -I puts its input in place of
    while argv and os.path.basename(argv[0]) in _WRAPPERS:
        wrapper = os.path.basename(argv.pop(0))
        if wrapper == "env":
            argv, env = _env(argv, child(), out, replaced)
            child = lambda env=env: env
            continue
        fed = fed or wrapper == "xargs"
        if wrapper in ("sudo", "doas"):
            env = _reset(child())
            child = lambda env=env: env
        run_words = edit = False
        while argv and (argv[0].startswith("-") or argv[0].replace(".", "").isdigit()
                        or argv[0] == "{}" or _ASSIGN.fullmatch(argv[0]) or _sudo_entry(wrapper, argv[0])):
            option = argv.pop(0)
            if option == "--":
                break
            if wrapper == "sudo" and not option.startswith("-"):  # NAME=VALUE, or a {} xargs may fill in with one
                _known_entry(option.split("=", 1)[0], replaced)
            if _ASSIGN.fullmatch(option) or _sudo_entry(wrapper, option):
                if wrapper == "sudo" and _ASSIGN.fullmatch(option):  # sudo p=x cmd: where the policy lets it, cmd has p=x
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
            if key in _WRAPPER_REPLACES:
                replaced.append(value or "{}")
        if wrapper == "sudo" and argv and not edit:
            _known_entry(argv[0], replaced)  # "$a", *: sudo takes it for NAME=VALUE if it is one
        if edit:
            argv = ["sudoedit", *argv]
        if wrapper == "watch" and argv and not run_words:  # watch hands its words to sh -c
            argv = ["sh", "-c", " ".join(argv)]
    return argv, fed, child


class _Function:
    """The body of a function as it was defined: its tokens and the substitutions they mark. It
    is read where it is called (#60). Two are the same when they are written the same."""

    def __init__(self, tokens: list, runs: list):
        self.tokens, self.runs = tokens, runs
        self.key = (tuple((t, t.raw, t.op, t.fd, t.plain, None if t.array is None else tuple(t.array)) for t in tokens), tuple(runs))

    def __eq__(self, other) -> bool:
        return isinstance(other, _Function) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)


class _Context:
    """What the reading of one command keeps across the texts it reads: the functions it defines,
    the traps it sets, and how much it has read. Which body a function's name has where it is
    called is kept with the variables, under NAME(): a definition in a branch, a subshell or a
    `bash -c` may not replace the one before it (#61)."""

    def __init__(self, out: Command):
        self.out = out
        self.bodies: set[_Function] = set()  # every body defined, wherever
        self.defined: set[str] = set()       # and the names they are defined under
        self.calls: list[str] = []           # the functions being read, innermost last
        self.called: set[_Function] = set()  # the bodies read where they are called
        self.traps: dict[tuple, list] = {}   # (text, depth): [what the variables may hold while it may run, signals]
        self.work = 0

    def finish(self, end: dict) -> None:
        """What runs after the command has been read, or at a time it does not show. A trap runs
        when its signal comes or the shell exits (end): it is read with all the variables may hold
        from where it was set, and one that changes them at another time than the exit, the
        command cannot be read with. A function body that is defined and not read where it is
        called may still be called (a name made at run time, a sourced file): it is read once,
        with what the variables hold at the end."""
        for held in self.traps.values():
            held[0] = _union(held[0], end)
        done = set()
        while len(done) < len(self.traps) or self.bodies - self.called:
            for key in [k for k in self.traps if k not in done]:
                done.add(key)
                env, signals = self.traps[key]
                after = _read(key[0], self, env, key[1])
                if signals - {"EXIT", "0"} and _grows(after, env):
                    raise ValueError("a trap that changes variables at a time that cannot be told")
            for body in list(self.bodies - self.called):
                self.called.add(body)
                _walk(body.tokens, body.runs, self, end, 0)


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
        self.function = None           # the body of this function, being defined: it runs where it is called
        self.cut = False               # a return, break, continue or exit was read in it: what follows may not run


def read(cmd: str, cwd: str = "") -> Command:
    cmd = "".join(ch for ch in cmd if ch not in ("\0", _MARK, _OPAQUE, _FIELD, _FIELD_END))
    # The hook runs in the environment Claude Code gives its commands, so a variable set there
    # has the value the command saw (_values). Only what neither that nor the command itself sets is unknown.
    out, env = _shell(cmd, cwd, {"HOME": (os.path.expanduser("~"),), "PWD": (cwd,)}, 0)
    visible = _SINGLE_QUOTED.sub("''", _prepare(cmd))  # '$1' in an awk program is not a shell variable
    used = {a or b for a, b in _VAR.findall(visible)}
    unset = used - set(env) - set(os.environ) | used & {"_"}  # $_: never known (_values)
    out.dynamic = bool(_DYNAMIC.search(visible) or unset)
    # read, mapfile and readarray give variables words of what they read, which may be any text
    # the command prints: each word it may be split into is a path the command names (#74). So
    # are the words a value not known may be split into at IFS (`touch $(echo '.claude x')`).
    # What a program prints may differ from its words: escapes, a \c, a NUL (_printed), and
    # printf's format, which joins or cuts them (_printf). The whole of each, without the line
    # breaks $(...) takes off its end, is a path the command names too (`"$(printf '%b' '/\c')"`).
    splits = out.breaks or any(os.path.basename(argv[0]) in ("read", "mapfile", "readarray") for argv in out.programs)
    for argv, dirs in zip(list(out.programs), list(out.program_dirs)):
        texts = [(a, _printed(a)) for a in argv[1:]]
        texts += [(p, _received(p)) for p in (_printf(argv[1:]) if os.path.basename(argv[0]) == "printf" else [])]
        named = {f.rstrip("\n") for text, forms in texts for f in forms} - set(argv[1:]) - {""}
        if splits:
            named |= {p for text, forms in texts for p in _pieces(text, out.breaks, forms)}
        for piece in named:
            _note_paths(piece, dirs, out.paths, out.globs)
    # The home that a script a shell or ssh runs names does not make that shell a change only if
    # the script cannot hand it to anything this does not read (_closed). A script made only of
    # programs that read cannot; what it prints can, through a file the command writes or a pipe
    # into a program that does not only read (`bash -c 'echo ...' | tee s.sh`): then it counts
    # again, as it did before #70. Of the programs that may write a file, not those that only
    # read (`ps -o comm=` names a column) nor the shells and ssh, whose -o and -O set options:
    # what they write, they write with a redirection, which is in out.writes.
    writers = Command()
    writers.writes = out.writes
    for argv, dirs, closed in zip(out.programs, out.program_dirs, out.program_closed):
        if not closed and os.path.basename(argv[0]) not in _SHELLS | {"ssh"}:
            writers.programs.append(argv)
            writers.program_dirs.append(dirs)
    quiet = not written_paths(writers) - _NOWHERE and not (out.piping and not all(out.program_closed))
    for paths, carried, closed in zip(out.program_paths, out.program_carried, out.program_closed):
        if not (closed and quiet):
            paths |= carried
    return out


def _shell(cmd: str, cwd: str, env: dict, depth: int, within: _Context | None = None) -> tuple[Command, dict]:
    """cmd read as a shell of its own, started in cwd with the variables holding what env says:
    what it runs, and what they may hold when it has ended. Its functions, its traps and the
    directories it goes to are its own, and what it leaves to run at its end is read there.
    within: the reading it is part of, whose limit on how much is read it shares."""
    out = Command(cwd)
    ctx = _Context(out)
    ctx.work = within.work if within else 0
    env = _read(cmd, ctx, env, depth)
    ctx.finish(env)
    if within:
        within.work = ctx.work
    if ctx.defined & set(_TR) or any(argv[0] == "alias" for argv in out.programs):
        # `tr() { rm -rf "$1"; }; tr / _`: the tr run is the command's own, and its words are
        # what that is given
        for paths, globs, (more, more_globs) in zip(out.program_paths, out.program_globs, out.program_sets):
            paths |= more
            globs += more_globs
            out.paths |= more
            out.globs += more_globs
    return out, env


def _add(out: Command, there: Command) -> None:
    """What a shell of its own ran and named, added to the command that started it. Not the
    directories it went to: they are not this command's."""
    for mine, its in ((out.programs, there.programs), (out.program_dirs, there.program_dirs),
                      (out.program_paths, there.program_paths), (out.program_globs, there.program_globs),
                      (out.program_fed, there.program_fed), (out.program_sets, there.program_sets),
                      (out.program_closed, there.program_closed), (out.program_carried, there.program_carried),
                      (out.assigned, there.assigned)):
        mine.extend(its)
    out.piping = out.piping or there.piping
    out.breaks |= there.breaks
    out.writes |= there.writes
    out.paths |= there.paths
    out.globs += there.globs


def _read(cmd: str, ctx: _Context, env: dict, depth: int, inline: bool = True) -> dict:
    """Read cmd into ctx.out, with the variables holding what env says, and return what they may
    hold once it has run."""
    text, runs = _lift_substitutions(_prepare(cmd) if inline else cmd)
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
    inpipe = False   # or it is inside a part of a pipeline that is: `... | (bash)`, `... | while ...; do sh; done`

    def expand(word: str, env: dict) -> dict:
        """The word is expanded, with the variables holding what env says: what they hold after
        (_assigned). Each $(...) in it runs before the word is used, with what they hold then and
        may hold by the end of the word, and what it sets stays in it."""
        if silent:
            return env
        env = _assigned(word, env, runs)
        for n in _RUN.findall(word):
            _read(runs[int(n)], ctx, env, depth, inline=False)
        return env

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
        nonlocal piped, inpipe
        words, after, f.words, f.closed = f.words, f.closed, [], None
        if silent:
            f.head = False
            return
        if f.head:  # words to loop over or to match, not a program
            f.head = False
            env = env_in(f)
            for word in words:
                env = expand(word, env)
            readings = _readings(words, env, split=words[0] != "case", breaks=out.breaks)  # case WORD is not split
            for argv in readings:
                for arg in argv[1:2] if argv[0] == "case" else argv[3:]:  # case WORD in, for NAME in WORDS
                    _note_paths(arg.replace(_LITERAL, "$"), out.dirs, out.paths, out.globs)
            if words[0] != "case" and len(words) > 1 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", words[1]):
                # NAME holds each word in turn; without `in`, each argument the shell was given
                each = [a for argv in readings for a in argv[3:]] if words[2:3] == ["in"] else [None]
                env = {**env, words[1]: tuple(dict.fromkeys(each)) or (None,)}
                out.assigned.append(str(words[1]))
            if env is not env_in(f):
                part(f, env, ";")
                f.entry = f.env
            return
        if words:  # after a closed part, its redirections: `done > log`
            piped = f.pipe is not None
            inpipe = any(frame.pipe is not None for frame in frames)
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
            body = _Function(toks[f.at:i], runs)
            ctx.bodies.add(body)
            ctx.defined.add(f.function)
            frames[-1].closed = {**f.start, f"{f.function}()": (body,)}
        elif kind != "<(":  # a <( ... ) runs beside the command it is in, which goes on
            frames[-1].closed = _union(f.start, f.env)

    def again(f: _Frame) -> bool:
        """At the `done` of loop f. When a pass may leave a value that the pass after it begins
        with and this one did not, or a function body, the loop is read again from its first
        word with that (#56), and whatever was read in it is read anew. True if it is."""
        nonlocal i, carry, passes
        settle(f)
        if silent or not _grows(f.env, f.entry):
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

    def assign(word: _Token, env: dict, expanding: bool) -> tuple[str, tuple, dict]:
        """NAME=VALUE, NAME+=VALUE, NAME[I]=VALUE, NAME=(A B): the name, the values it may hold
        after, and what the variables hold once its value is expanded (expanding: here; else it was
        as a word of the command). What it is given is a path the command names: a program fed
        from elsewhere may be given it (_note_paths)."""
        name, index, plus, value = _ASSIGN_PARTS.fullmatch(word).groups()
        if index:  # a subscript is arithmetic
            env = _arithmetic(index[1:-1], env)
        if word.array is not None:
            for element in word.array:
                env = expand(element, env)
            values = tuple(dict.fromkeys(f for e in word.array for r in _readings([e], env) for f in r)) or ("",)
        else:
            if expanding:
                env = expand(value, env)
            values = tuple(dict.fromkeys(r[0] for r in _readings([value], env, split=False)))
        for v in values:
            for piece in [v, *_pieces(v)]:  # and each word the shell may split it into (#74)
                _note_paths(piece.replace(_LITERAL, "$"), out.dirs, out.paths, out.globs)
        if plus and not index and word.array is None:  # p+=x: x after each value p may hold, and after ${p}
            values = tuple(dict.fromkeys((old if old is not None else "$" + _OPAQUE + "{" + name + "}") + v
                                         for old in _values(env, name) for v in values))
        elif index or plus:  # one element, or more: the others are still there
            values = _merge(_values(env, name), values)
        return name, values, env

    def declare(command: list[_Token], env: dict) -> dict | None:
        """export, declare, local, readonly, typeset as written: the variables they set, whose
        values are expanded before they run, and with `builtin` or `command` in front of them.
        A name reference (-n), and an integer variable (-i), whose values are arithmetic, the
        command cannot be read with."""
        k = 0
        while k + 1 < len(command) and command[k].plain and command[k] in ("builtin", "command"):
            k += 1
        builtin = command[k]
        if not (builtin.plain and builtin in _DECLARE):
            return None
        declared, before = {}, env
        for word in command[k + 1:]:
            if word.startswith(("-", "+")) and word.array is None:
                if builtin != "export" and "n" in word[1:]:
                    raise ValueError("a name reference")
                if word.startswith("-") and "i" in word[1:]:
                    raise ValueError("an integer variable")
                if "f" in word[1:] or "F" in word[1:]:
                    break  # functions, not variables
            elif word.array is not None or _ASSIGN_PARTS.fullmatch(word):
                name, values, env = assign(word, env, False)
                declared[name] = values
            elif builtin in ("local", "declare", "typeset") and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
                declared[word] = _merge(_values(env, word), (None,))  # in a function: a variable of its own
        return {**{name: values for name, values in env.items() if before.get(name) is not values}, **declared}

    def declared_as_run(argv: list[str], env: dict) -> dict:
        """export, declare and the rest as they run, with their words expanded: "$n=x" gives a
        value to the variable n names, and a name that is not known may be any variable's."""
        for word in argv[1:]:
            if word.startswith(("-", "+")):
                if "f" in word[1:] or "F" in word[1:]:
                    break
                continue
            if "$" in word.split("=", 1)[0]:
                return _unknown(env)
            m = _ASSIGN_PARTS.fullmatch(word)
            if m:
                env = {**env, m.group(1): _merge(_values(env, m.group(1)), (m.group(4),))}
        return env

    def sets(argv: list[str], env: dict, scope: dict) -> dict:
        """read, mapfile, getopts, printf -v, wait -p, unset: variables given values the command
        does not show. A name that is not known (`read "$x"`) may be any variable's. Where read
        ends a value, at the characters of IFS as it runs (scope), at a line break or the
        delimiter of -d, a word of what it reads ends: they are among out.breaks (#74). Where
        they are not known, which words it gives cannot be told."""
        program, args = argv[0], _operands(argv)[1:]
        if program in ("mapfile", "readarray") and any(a.startswith("-") and "C" in a for a in args):
            raise ValueError("a callback the shell runs")
        valued = {"read": "adinNptu", "mapfile": "dnOsuc", "readarray": "dnOsuc", "printf": "v", "wait": "p"}
        naming = {"read": "a", "printf": "v", "wait": "p"}  # options whose value is a variable
        ifs = list(_ifs(scope)) if program == "read" else []
        ends = ["\n"] if program in ("read", "mapfile", "readarray") else []
        named, operands, k = [], [], 0
        while k < len(args):
            a, k = args[k], k + 1
            if a == "--" or not a.startswith("-") or a == "-":
                operands = args[k - (a != "--"):]
                break
            if program == "unset" and set(a[1:]) & {"f", "n"}:
                return env  # functions, whose bodies may still be there; or a name reference
            for j, letter in enumerate(a[1:], 2):
                if letter in valued.get(program, ""):
                    if letter in naming.get(program, ""):
                        named.append(a[j:] or (args[k] if k < len(args) else ""))
                    if letter == "d" and program in ("read", "mapfile", "readarray"):  # -d '': at a NUL
                        ends.append(a[j:] or (args[k] if k < len(args) else "") or "\0")
                    if letter in "nN" and program == "read":  # read -n 1 a <<< /x gives /
                        raise ValueError("a read of a number of characters, which may end anywhere")
                    k += not a[j:]
                    break
        for chars in ifs + ends:
            if chars is None or "$" in chars or _OPAQUE in chars:
                raise ValueError("a read that ends words at characters that are not known")
        # A read into one name does not split the line: it takes off the spaces, tabs and
        # newlines of IFS at either end, and one other character of IFS at the end (`IFS=x read
        # a <<< /x` gives /). Into more, or an array, it splits at each character of IFS.
        words = bool(named) or len(operands) > 1 or any("$" in a or _OPAQUE in a for a in operands)
        out.breaks.update(ch for chars in ends for ch in chars)
        out.breaks.update(ch for chars in ifs for ch in chars if words or ch not in " \t\n")
        if program == "read":
            names = named + operands or ["REPLY"]
        elif program in ("mapfile", "readarray"):
            names = operands[-1:] or ["MAPFILE"]
        elif program == "getopts":
            names = operands[1:2]
        elif program == "unset":
            names = operands
        else:
            names = named
        env = dict(env)
        for name in names:
            if "$" in name:
                return _unknown(env)
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", name)
            if m:
                env[m.group(0)] = (None,) if program == "unset" else _merge(_values(env, m.group(0)), (None,))
        return env

    def trap(args: list[str], env: dict) -> None:
        """trap TEXT SIGNALS: TEXT runs later, and is read later (_Context.finish)."""
        if args[:1] == ["--"]:
            args = args[1:]
        if len(args) < 2 or args[0] in ("", "-", "-p", "-l"):
            return
        key = (args[0].replace(_LITERAL, "$"), depth)
        signals = {s.upper().removeprefix("SIG") for s in args[1:]}
        held = ctx.traps.get(key)
        ctx.traps[key] = [_union(held[0], env), held[1] | signals] if held else [env, signals]

    def call(name: str, body: _Function, env: dict) -> dict:
        """A function runs its body in this shell, with what the variables hold where it is
        called (#60). What it sets may stay after it, beside what they held before."""
        if len(ctx.calls) >= _CALLS:
            raise ValueError("functions that call each other deeper than can be read")
        ctx.calls.append(name)
        ctx.called.add(body)
        try:
            return _union(env, _walk(body.tokens, body.runs, ctx, env, depth))
        finally:
            ctx.calls.pop()

    def simple(words: list[_Token], start: dict) -> dict:
        """One simple command, read once for each combination of the values its variables may
        hold: what they hold after it."""
        for held in ctx.traps.values():  # a trap set before may run while this does
            held[0] = _union(held[0], start)
        assigns, command, redirects = _parts(words)
        env, envs = start, []
        for word in command:  # the shell expands these first, in turn: ${p:=x} in one reaches the next (#64)
            env = expand(word, env)
            envs.append(env)
        scope = env  # what the command itself is run with
        for word in assigns:  # then these in turn: after `a=1 b=$a`, b is 1, and in b=$(...) too (#55)
            name, values, scope = assign(word, scope, True)
            scope = {**scope, name: values}
            out.assigned.append(name)
        # A redirection, bash expands after the assignments of a command without a program, dash before.
        late = _union(env, scope) if assigns and redirects else env
        for word in redirects:
            late = expand(word, late)
            envs.append(late)
            env, scope = _assigned(word, env, runs), _assigned(word, scope, runs)
        if not command:  # p=x, p=x >f, >f p=x: the assignments stay in this shell (#57)
            for argv in _readings(redirects, late, envs) if redirects else []:
                _program(argv, False, scope, lambda: scope)
            return scope
        declared = declare(command, env)
        made = []

        def child() -> dict:  # what a program the command starts finds in its environment
            if not made:
                made.append(_exported(scope, {_ASSIGN_PARTS.fullmatch(w).group(1) for w in assigns}))
            return made[0]
        written = all(_as_written(w) for w in command)
        return _union(*[run(argv, env, scope, child, declared, bool(assigns), written)
                        for argv in _readings(command + redirects, env, envs, split=command[0] != "[[",
                                              breaks=out.breaks)])

    def run(argv: list[str], start: dict, scope: dict, child, declared: dict | None, prefixed: bool,
            written: bool = False) -> dict:
        """One reading of a simple command: what the variables hold after it. written: each of its
        words is one word as written, with nothing in it the shell expands (_as_written)."""
        while len(argv) > 1 and argv[0] == "":  # a variable that holds nothing, unquoted, is no word
            argv = argv[1:]
        if not argv:  # nothing left to run (`$empty`): the assignments in front stay in this shell
            return _union(start, scope) if prefixed else start
        builtin = _builtin(argv)
        name, after = (builtin[0] if builtin else ""), start
        if prefixed and os.path.basename(name) in _SPECIAL_BUILTINS:
            after = _union(start, scope)
        if declared is not None:
            after = {**after, **declared}
        if name in _DECLARE:
            after = declared_as_run(builtin, after)
        elif name in _SETS:
            after = sets(builtin, after, scope)
        elif name in _LEAVES:
            leave(name)
        elif name == "trap":
            trap(builtin[1:], start)
        elif name == "let":
            for a in _operands(builtin)[1:]:
                after = _arithmetic(a, after)
        elif name == "[[":  # the operands of -eq and the like are arithmetic
            for k, a in enumerate(builtin[2:-1], 2):
                if a in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
                    after = _arithmetic(builtin[k + 1], _arithmetic(builtin[k - 1], after))
        elif name in (".", "source") or "$" in name:  # runs in this shell what the command does not show
            after = _unknown(after)
        elif name in ("cd", "pushd", "popd"):  # the directory it went to, or still the one before
            after = {**after, **{v: _merge(_values(after, v), (None,)) for v in ("PWD", "OLDPWD")}}
        if builtin is argv:  # builtin f and command f run no function
            for body in _values(scope, f"{name}()"):
                if body is not None:
                    after = _union(after, call(name, body, scope))
        if "$" in argv[0]:  # a program picked at run time may be any of the functions
            for key in [k for k in scope if k.endswith("()") and k[:-2] not in ctx.calls]:
                for body in _values(scope, key):
                    if body is not None:
                        after = _union(after, call(key[:-2], body, scope))
        if any(_IMPORTS in a for a in argv):
            # BASH_FUNC_tr%%=() { ...; } in an environment: bash, there or in any program it starts,
            # takes it for a function named tr (#69), whose body this does not read
            raise ValueError("an environment entry a shell takes for a function")
        argv, fed, child = _unwrap(argv, child, out)
        if argv:
            evaluated = _program(argv, fed, scope, child, written)
            if evaluated is not None:  # eval runs its text in this shell
                after = _union(evaluated, start) if prefixed else evaluated
        return after

    def nest(text: str, env: dict) -> dict:
        if depth >= _DEPTH:
            raise ValueError("shells inside shells deeper than can be read")
        return _read(text, ctx, env, depth + 1)

    def _program(argv: list[str], fed: bool, scope: dict, child, written: bool = False) -> dict | None:
        """Record one program. For eval, returns what the variables hold after the text it runs.
        A shell it starts (bash -c) is read with child(), what that shell finds in its environment."""
        fed = fed or any("$" in a for a in argv)  # a $ in single quotes (_LITERAL) is text, not a value
        text = [a.replace(_LITERAL, "$") for a in argv]  # as a shell that reads it later has it
        raw = [a.replace(_OPAQUE, "") for a in text]
        operands = _operands(raw)[1:]
        program = os.path.basename(raw[0])
        # its input is the pipe's, unless it is given another
        from_pipe = piped or inpipe and not any(a in ("<", "<<<") for a in raw[len(operands) + 1:])
        if from_pipe and _INTERPRETER.fullmatch(program) and \
                all(a.startswith("-") and a not in ("-c", "-e", "-E", "-m", "-r") for a in operands):
            fed = True  # `echo '...' | python3`: its program, and the paths in it, come through the pipe
        # What source, a shell or an interpreter runs may be a file the command made, as may a
        # program run by its path: `source <(echo ...)`, `echo ... > s.sh; bash -e s.sh`,
        # `... | tee s.py; python3 -W ignore s.py`, `./s.sh`. Then what it runs is the command's
        # own, as with eval "$(...)". Any of its words may name the file, whatever its options
        # mean, and any program that writes one may have made it (written_paths).
        runs = program in (".", "source") or program in _SHELLS or bool(_INTERPRETER.fullmatch(program))
        if runs or "/" in raw[0]:
            files = set(resolve(raw[0], out.dirs)) if "/" in raw[0] else set()
            if runs:
                files.update(p for a in raw[1:] if a for p in resolve(a, out.dirs))
            if (runs and any(_FROM_PIPE.fullmatch(a) for a in raw[1:])) or files & written_paths(out):
                fed = True
        out.programs.append(raw)
        out.program_fed.append(fed)
        out.program_dirs.append(list(out.dirs))
        paths: set[str] = set()
        globs: list[str] = []
        out.program_paths.append(paths)
        out.program_globs.append(globs)
        sets: tuple[set[str], list[str]] = (set(), [])
        out.program_sets.append(sets)
        carried: set[str] = set()
        out.program_carried.append(carried)
        me = len(out.program_closed)
        out.program_closed.append(program not in _SHELLS and program != "ssh" and _only_reads(raw, fed)
                                  and _plain(child()))
        out.piping = out.piping or from_pipe
        charset = _set_operand(raw) if written and not fed else 0
        # What ssh runs on the other host: its command, and what it sends there to a shell that
        # reads its commands from it (a here-document, a here-string). The host may be this one or
        # share its home, so both are read as commands run here (#73), wherever the command
        # appears to begin: that only adds to what is asked about. The home and the directories
        # above it that they name are carried: they make ssh a change only where they may reach
        # something this does not read (read()), but the command still names them, for a program
        # given a value later (#71). That only where the command's beginning is certain, each word
        # being one word as written and none coming from elsewhere: one that vanishes moves the
        # destination, and an option after it runs here (#72).
        remote = _ssh_command_at(raw) if program == "ssh" else 0
        sent = " ".join(text[remote:len(operands) + 1]) if remote else ""
        takes = _reads_commands(sent) if remote else False
        here = max((i for i in range(2, len(raw)) if raw[i - 1] == "<<<"), default=0)
        script = here if takes is not False else 0
        if remote and from_pipe and takes is not False and not any(a in ("<", "<<<") for a in raw[len(operands) + 1:]):
            raise ValueError("a shell that reads its commands from a pipe")  # `echo 'rm ...' | ssh host`
        apart = remote if written and not fed else 0
        # A script a shell here is given, in its -c string or as the input it reads its commands
        # from, is read as commands as well (below), as if it stood in place of the shell: what
        # it names is carried in the same way. Where it is depends on all of the shell's options
        # (_shell_call): after `bash notes.sh -c`, -c is the script's (#77).
        call = _shell_call(raw) if program in _SHELLS else None
        scripts: set[int] = set()
        if call and written and not fed:
            scripts = {call[1]} if call[0] == "command" else \
                {i for i in range(2, len(raw)) if raw[i - 1] == "<<<" and call[0] == "stdin"}
        home = canonical("~")
        for i, arg in enumerate(argv[1:], 1):
            there = (apart and (apart <= i <= len(operands) or i == script)) or i in scripts
            named: set[str] = set() if there else paths
            for form in _wider(arg, scope):
                _note_paths(form, out.dirs, *(sets if i == charset else (named, globs)))
            if there:
                out.paths |= named
                carried.update(p for p in named if under(home, p))
                paths.update(p for p in named if not under(home, p))
            if raw[i - 1] == "<<<":  # what read makes of a here-string or a here-document (#74)
                for piece in _pieces(raw[i]):
                    _note_paths(piece, out.dirs, out.paths, out.globs)
            if ">" in raw[i - 1] and set(raw[i - 1]) <= _REDIRECT_CHARS and not (
                    raw[i - 1].endswith("&") and (raw[i].isdigit() or raw[i] == "-")):  # 2>&1 writes no file
                for target in expand_braces(raw[i]):
                    out.writes.update(resolve(target, out.dirs))
        out.paths |= paths
        out.globs += globs
        # The command lines ssh, scp and sftp are given in -o options, and rsync its ssh in -e and
        # RSYNC_RSH: RemoteCommand and --rsync-path run on the other host, the others here
        # (ssh -o ProxyCommand='...').
        options = _ssh_option_commands(text[:remote] if remote else text[:len(operands) + 1]) \
            if program in ("ssh", "scp", "sftp") else []
        if program == "rsync":
            options = _rsync_commands(text[:len(operands) + 1]) + [
                (v.replace(_LITERAL, "$"), False) for v in _values(child(), "RSYNC_RSH")
                if v is not None and v != os.environ.get("RSYNC_RSH")]
        for line in [line for line, away in options if not away]:
            nest(line, child())
        elsewhere = ([sent] if sent else []) + ([text[script]] if script else []) + \
            [line for line, away in options if away]
        closed = not any(not away for _, away in options) and _plain(child())
        if elsewhere:
            # Each runs in a shell of its own, which sshd starts in the home directory with HOME
            # and PWD set to it, whatever they hold here. What it sets, the directories it goes
            # to and the traps it leaves stay there, and are read there; what it runs and
            # names is this command's.
            if depth >= _DEPTH:
                raise ValueError("shells inside shells deeper than can be read")
            there = {**child(), "HOME": (home,), "PWD": (home,), "OLDPWD": (None,)}
            for n, commands in enumerate(elsewhere):
                part = _shell(commands, home, there, depth + 1, ctx)[0]
                for k, each in enumerate(part.programs):
                    # its traps are read there, and so is the script it sends a shell that reads
                    # its commands from its input (`ssh host 'bash -s' <<'EOF'`)
                    if each[0] == "trap" or (n == 0 and sent and script and takes and
                                             os.path.basename(each[0]) in _SHELLS and _shell_call(each) == ("stdin", 0)):
                        part.program_closed[k] = True
                closed = closed and _closed(part.program_closed, part.assigned, commands)
                _add(out, part)
        if program == "ssh":
            out.program_closed[me] = closed
        if program == "cd":
            targets = [a for a in raw[1:] if not a.startswith("-")][:1] or \
                [home for home in _values(scope, "HOME") if home is not None]
            out.dirs.extend([canonical(t, d) for t in targets for d in out.dirs[:8]])
        if program in _SHELLS and (piped and not (call and call[0] == "command") or
                                   from_pipe and (call is None or call[0] == "stdin")):
            raise ValueError("a shell that reads its commands from a pipe")  # `echo 'rm ...' | bash -s -- -c`, `| (bash)`
        if program in _TAKES_COMMAND:
            shell_env = _reset(child()) if program == "su" else child()
            if any(_IMPORTS in name and any(v is not None and v != os.environ.get(name) for v in values)
                   for name, values in shell_env.items()):  # a function this shell imports from the command (#69)
                raise ValueError("an environment entry a shell takes for a function")
            first, assigned = len(out.programs), len(out.assigned)
            code = scripts | ({call[1]} if call and call[0] == "command" else set())
            for i, arg in enumerate(text[1:], 1):
                # its script, and where that cannot be told the string after anything like -c; for
                # a shell also any argument with spaces in it: a script given as a here-document
                # arrives that way. A shell of its own: what it sets stays there.
                if i in code or (not call and re.fullmatch(r"-\w*c", raw[i - 1])) or \
                        (program in _SHELLS and re.search(r"\s", arg)):
                    nest(arg, shell_env)
            if program in _SHELLS:
                # a trap it sets runs at the end of this command, outside what is read here: trap
                # is not among the programs that only read
                out.program_closed[me] = bool(scripts) and _plain(shell_env) and _closed(
                    out.program_closed[first:], out.assigned[assigned:], *(text[i] for i in scripts))
        elif program == "eval":
            return nest(" ".join(text[1:]), scope)
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
            env = expand(token, env_in(f))
            if env is not env_in(f):
                part(f, env, ";")
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
                        loop.at, loop.snapshot = i - 1, snapshot
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


def _operands(argv: list[str]) -> list[str]:
    """A program and its arguments, up to its redirections, which _parts puts after its words."""
    for k, a in enumerate(argv[1:], 1):
        if _REDIRECTION.fullmatch(a) or (_FD.fullmatch(a) and _REDIRECTION.fullmatch((argv[k + 1:] or [""])[0])):
            return argv[:k]
    return argv


_TR = ("tr", "/usr/bin/tr", "/bin/tr")  # and a function the command defines may have any of these names


def _as_written(word: str) -> bool:
    """The shell gives the word to the program as one word, as it is written: there is nothing in
    it that it expands, splits or matches against file names. An empty variable or a glob that
    matches nothing is no word at all (#68), and a brace or a variable may be several. A word that
    ends in @, + or ! may begin an extended glob, @(x), which this takes for the word and a ( ... )
    after it."""
    return not re.search(r"[$`*?\[{" + _MARK + _OPAQUE + "]|[@+!]$", word)


def _set_operand(raw: list[str]) -> int:
    """Where tr's first set (`/` in `tr / _`) is among the words, or 0. tr opens no file, and the
    characters of that set are the ones it takes out of what it reads or puts others in place
    of: what it writes has none of them that was not in what it read. So it names no path,
    and none that $(... | tr / _) may give another program. Only for a command whose words are
    each one word as written (_as_written), and not when the set is the last of them: the next
    command has that as $_."""
    if raw[0] not in _TR:
        return 0
    words = _operands(raw)
    k = 1
    while k < len(words) and words[k].startswith("-") and words[k] != "-":  # none of its options takes a value
        k += 1
        if words[k - 1] == "--":
            break
    return k if k < len(words) - 1 else 0


_SSH_VALUE_OPTS = set("BbcDEeFIiJLlmOoPpRSWw")  # ssh's options whose value is the rest of the word or the next one
_SSH_FLAGS = set("46AaCfGgKkMNnqsTtVvXxYy")


def _ssh_command_at(argv: list[str]) -> int:
    """Where among ssh's words the command it runs on the other host begins (one past its last
    word when it is given none), or 0 when that cannot be told: an option this does not know.
    Options may stand before and after the destination, as OpenSSH reads them in both places;
    the first other word after it begins the command, and so does the word after `--`. Only for
    words that are each one word as written (_as_written): the reader keeps an empty value as
    a word, and `-l $empty user host` would take user for the destination (#72)."""
    words = _operands(argv)
    k, host = 1, 0
    while k < len(words):
        word = words[k]
        if word == "--":
            k += 1 if host else 2  # ssh -- host command
            return k if k <= len(words) else 0
        if word.startswith("-") and len(word) > 1:
            for j, letter in enumerate(word[1:], 1):
                if letter in _SSH_VALUE_OPTS:
                    k += j == len(word) - 1  # -o Opt=x, and -oOpt=x with the value in it
                    break
                if letter not in _SSH_FLAGS:
                    return 0
            k += 1
        elif host:
            return k
        else:
            host, k = k, k + 1
    return k if host else 0


# ssh's options whose value is a command line, and whether it runs on the other host. The others
# run here: ssh starts ProxyCommand and LocalCommand with the user's shell, KnownHostsCommand itself.
_SSH_COMMAND_OPTIONS = {"proxycommand": False, "localcommand": False, "knownhostscommand": False,
                        "remotecommand": True}


def _ssh_option_commands(words: list[str]) -> list[tuple[str, bool]]:
    """The command lines given to ssh, scp or sftp in -o options (-o Key=Value, -o 'Key Value',
    -oKey=Value, -qo ...), with %d, which ssh fills in with the home, put in; and for each whether
    it runs on the other host. A word that only looks like such an option is taken for one: that
    adds to what is asked about."""
    found = []
    for k, word in enumerate(words[1:], 1):
        if not word.startswith("-") or word.startswith("--") or "o" not in word:
            continue
        value = word[word.index("o") + 1:] or (words[k + 1] if k + 1 < len(words) else "")
        option = re.match(r"\s*([A-Za-z]+)\s*(?:=\s*|\s+)(.*)", value, re.S)
        if option and option.group(1).lower() in _SSH_COMMAND_OPTIONS:
            line = re.sub(r"%(.)", lambda t: {"d": canonical("~"), "%": "%"}.get(t.group(1), t.group(0)),
                          option.group(2))
            found.append((line, _SSH_COMMAND_OPTIONS[option.group(1).lower()]))
    return found


def _rsync_commands(words: list[str]) -> list[tuple[str, bool]]:
    """The command lines rsync is given: the shell it reaches the other host with (-e, --rsh),
    which runs here, and the rsync it runs there (--rsync-path); for each whether it runs on the
    other host. A word that only looks like such an option is taken for one."""
    found = []
    for k, word in enumerate(words[1:], 1):
        following = words[k + 1] if k + 1 < len(words) else ""
        name, eq, value = word.partition("=")
        if name in ("--rsh", "--rsync-path"):
            found.append((value if eq else following, name == "--rsync-path"))
        elif word.startswith("-") and not word.startswith("--") and "e" in word:
            found.append((word[word.index("e") + 1:] or following, False))
    return found


_FROM_PIPE = re.compile(r"/dev/(?:fd/\d+|stdin)|/proc/(?:self|\d+)/fd/\d+")  # `bash <(...)`, `| python3 /dev/stdin`
_NOWHERE = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}  # what is written there cannot be run

# The options of sh, bash and dash that take no value and leave alone where the shell takes its
# commands from. Not -i: an interactive shell first runs the commands in a file of its own.
_SHELL_FLAGS = set("abefhklmnprtuvxBCDEHIPTV")
_SHELL_LONG = {"--login", "--noediting", "--noprofile", "--norc", "--posix", "--restricted", "--verbose",
               "--debugger", "--version", "--help", "--pretty-print", "--dump-strings", "--dump-po-strings"}


def _shell_call(argv: list[str]) -> tuple[str, int] | None:
    """Where a shell takes its commands from: ("command", k), the string that is its word k
    (-c); ("stdin", 0), its input (-s, or no operand); ("file", k), the script its word k names.
    None when that cannot be told: an option this does not know, -i and --rcfile (a file of its
    own runs first), -c with -s (dash runs both). As bash and dash read them: every option before
    the first operand counts, also one after -c (`bash -c -x 'cmd'`); -o and -O take the next
    word (`bash -O extglob s.sh`); - and -- end the options, and the word after them is a script
    even when it is -c (`bash -- notes.sh -c ~`, #77)."""
    words = _operands(argv)
    k, letters = 1, ""
    while k < len(words):
        word = words[k]
        if word in ("-", "--"):
            k += 1
            break
        if word in _SHELL_LONG:
            k += 1
            continue
        if not re.fullmatch(r"[-+][A-Za-z]+", word):
            if word[:1] in ("-", "+") and len(word) > 1:
                return None
            break
        for j, letter in enumerate(word[1:], 1):
            if letter in "oO":  # its value is the next word, and nothing may follow it in this one
                if j < len(word) - 1 or k + 1 >= len(words):
                    return None
                k += 1
            elif letter not in _SHELL_FLAGS and not (word[0] == "-" and letter in "cs"):
                return None
        letters += word[1:] if word[0] == "-" else ""
        k += 1
    if "c" in letters:
        return None if "s" in letters or k >= len(words) else ("command", k)
    return ("stdin", 0) if "s" in letters or k >= len(words) else ("file", k)


def _reads_commands(command: str) -> bool | None:
    """Whether what ssh runs on the other host takes its commands from its input: the login
    shell when it is given no command, or a shell that reads them there (bash -s, sh). For
    anything else what ssh sends is data, which is not read as commands. None when that cannot
    be told: a shell whose options this does not know (_shell_call), one that is not the first
    word (`sudo bash -s`), an interpreter, or words this cannot split."""
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if not words:
        return True
    if os.path.basename(words[0]) not in _SHELLS:
        if any(os.path.basename(w) in _SHELLS or _INTERPRETER.fullmatch(os.path.basename(w)) for w in words):
            return None
        return False
    call = _shell_call(words)
    return None if call is None else call[0] == "stdin"


# Programs that write no file and run nothing, whatever they are given: what a script may hold for
# the home it names not to make the shell or ssh that runs it a change (_closed). Not test, [,
# printf %d, read -t, exit, shift or return: bash reads the value they are given as arithmetic,
# where a subscript runs what is in it (`x='a[$(...)]'; test "$x" -eq 1`). Not [[ for the same
# reason, nor anything that runs a program or a file: find, xargs, rg (--pre), less, awk.
_ONLY_READ = {"ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "du", "df", "stat", "wc", "cut", "tr", "nl",
              "od", "strings", "md5sum", "sha1sum", "sha256sum", "cmp", "diff", "jq", "realpath", "readlink",
              "basename", "dirname", "which", "type", "id", "whoami", "uname", "ps", "who", "pwd", "cd", "echo",
              "true", "false", ":"}
_TMUX_READS = {"list-panes", "lsp", "list-windows", "lsw", "list-sessions", "ls", "list-clients", "lsc",
               "display-message", "display", "show-options", "show", "show-window-options", "showw",
               "show-environment", "showenv", "has-session", "has"}
_SED_ADDRESS = r"(?:\d+(?:~\d+)?|\$|/(?:[^/\\\n]|\\.)*/[IM]?)"
# one sed command that prints, deletes or substitutes: not e, w, W, r or R, nor the e and w flags of s
_SED_COMMAND = re.compile(rf"\s*(?:{_SED_ADDRESS}(?:\s*,\s*{_SED_ADDRESS})?)?\s*!?\s*"
                          r"(?:[pdnNgGhHxz=l]|[qQ]\d*|s([^\\\n\w\s])(?:(?!\1)[^\\\n]|\\.)*\1(?:(?!\1)[^\\\n]|\\.)*\1[gpiImM\d]*)"
                          r"\s*(?:[;\n]|$)")
# The variables a script may set, beside those with a lowercase letter in their name: the others
# are the ones programs and the shell itself take as instructions (LD_PRELOAD, PATH, BASH_ENV, PS4).
_PLAIN = {"IFS", "HOME", "PWD", "OLDPWD", "LANG", "LANGUAGE", "TZ", "TERM", "COLUMNS", "LINES", "NO_COLOR"}
# where bash reads a value as arithmetic or a name, or sets one, inside a word: [[, $((, $[,
# a subscript, ${x:offset}, ${x:=y}, ${!x}, ${x@P}
_EVALUATES = re.compile(r"\[|\(\(|\$\{[^}]*(?:[!@=]|:[^-+?])|\bselect\b")


def _only_reads(raw: list[str], fed: bool) -> bool:
    """Whether the program writes no file and runs nothing, given these words (_ONLY_READ). fed:
    some of them are not known."""
    if "/" in raw[0] and os.path.dirname(raw[0]) not in ("/bin", "/usr/bin"):
        return False  # ./ls is not ls
    program, words = os.path.basename(raw[0]), _operands(raw)[1:]
    if program == "printf":  # a format of %s alone: %d reads its value as arithmetic, -v sets a variable
        words = words[1:] if words[:1] == ["--"] else words
        return bool(words) and not words[0].startswith("-") and "$" not in words[0] and \
            not re.search(r"%(?!%|[-+ #0]*\d*(?:\.\d*)?[sqb])", words[0])
    if program == "read":  # into variables a program does not take instructions from, with no number
        return not fed and all(re.fullmatch(r"-[rse]+|[a-z_]\w*", w) and _plain_name(w) for w in words if w != "IFS")
    if program == "sort":  # -o writes, --compress-program runs a program
        return not any(w.startswith(("--o", "--co")) or re.fullmatch(r"-[^-]*o.*", w) for w in words)
    if program == "sed":
        return _sed_reads(words)
    if program == "tmux":  # #(...) in a format runs a command, and `;` begins another tmux command
        k = 0
        while k < len(words) and words[k] in ("-L", "-S", "-2", "-u"):
            k += 2 if words[k] in ("-L", "-S") else 1
        return k < len(words) and words[k] in _TMUX_READS and not any("#(" in w or w.endswith(";") for w in words)
    return program in _ONLY_READ


def _sed_reads(words: list[str]) -> bool:
    """Whether sed is given only options that change nothing and scripts that only print, delete
    and substitute (_SED_COMMAND): no -i, no script file, no e or w."""
    scripts, operands, k = [], [], 0
    while k < len(words):
        word = words[k]
        if word in ("-e", "--expression") or re.fullmatch(r"-[nErsuz]+e", word):
            if k + 1 >= len(words):
                return False
            scripts.append(words[k + 1])
            k += 1
        elif word.startswith("--expression="):
            scripts.append(word.partition("=")[2])
        elif re.fullmatch(r"-[nErsuz]+", word) or word in ("--quiet", "--silent", "--regexp-extended", "--separate",
                                                          "--unbuffered", "--null-data", "--posix", "--sandbox"):
            pass
        elif word.startswith("-") and word != "-":
            return False
        else:
            operands.append(word)
        k += 1
    for script in scripts or operands[:1]:
        at = 0
        while at < len(script):
            match = _SED_COMMAND.match(script, at)
            if not match or match.end() == at:
                return False
            at = match.end()
    return bool(scripts or operands)


def _plain_name(name: str) -> bool:
    return bool(re.search(r"[a-z]", name)) or name in _PLAIN or name.startswith("LC_")


def _plain(env: dict) -> bool:
    """Whether every variable in env is one a program does not take instructions from (_PLAIN)."""
    return all(_plain_name(name) for name in env if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))


def _closed(closed: list[bool], assigned: list[str], *texts: str) -> bool:
    """Whether a script, read as commands, cannot hand what it names to anything this does not
    read: every program in it only reads (_only_reads), it sets no variable programs take
    instructions from, and its text has nothing bash reads as arithmetic (_EVALUATES)."""
    return all(closed) and all(_plain_name(name) for name in assigned) and \
        not any(_EVALUATES.search(text) for text in texts)


def resolve(name: str, dirs: list[str]) -> list[str]:
    """A file name as canonical paths: one if it is absolute, else one per directory the command
    may be in (after `cd` inside a subshell or a pipeline the real one is not known)."""
    if os.path.isabs(os.path.expanduser(name)):
        return [canonical(name)]
    return [canonical(name, d) for d in dirs]


_OPERAND = re.compile(r"\$\{!?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?(:?[-=+?]|/[/#%]?|##?|%%?)([^{}]*)\}")


def _note_paths(arg: str, dirs: list[str], paths: set, globs: list) -> None:
    """Record the paths one argument names, and those in what an expansion left in it may give:
    `${p/#0/x}` and `${p:+x}` on a value that is not known may be x."""
    arg = arg.replace(_OPAQUE, "")
    for m in _OPERAND.finditer(arg):
        for operand in m.group(2).split("/", 1) if m.group(1)[0] == "/" else [m.group(2)]:
            _note_paths(operand, dirs, paths, globs)
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
