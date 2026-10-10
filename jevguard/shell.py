"""Just enough shell reading to see which programs a command runs and which files it names.

This is pattern reading, not a shell. It follows what a command says in plain sight: programs,
their arguments, `cd`, variables assigned in the same command, `bash -c '...'`, `find -exec`,
redirections, globs. It cannot follow a script that opens a file, an alias, or a value computed
at run time; `Command.dynamic` says when part of the command is of that kind.
"""

from __future__ import annotations

import fnmatch
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
_VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
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


def simple_commands(cmd: str) -> list[list[str]]:
    """The command cut at ; | & and parentheses, each piece as its words. Nothing is expanded and
    no wrapper is removed: this is what was written, for callers that accept only plain forms."""
    out, current = [], []
    for token in tokens(cmd):
        if token and set(token) <= _SEPARATORS:
            out.append(current)
            current = []
        else:
            current.append(token)
    return [words for words in [*out, current] if words]


def without_redirections(words: list[str]) -> list[str]:
    """The words a program is given, without `> file`, `>&1`, `< file` and the like."""
    out, skip = [], False
    for w in words:
        if skip:
            skip = False
        elif w and set(w) <= _REDIRECT_CHARS:
            skip = True
        else:
            out.append(w)
    return out


def expands(cmd: str) -> bool:
    """The shell would rewrite part of this command before running it: a variable or a command
    substitution anywhere but in single quotes, a brace list or a glob outside quotes. What then
    runs is not what is written. A lone `?` is let through: addresses are full of them. So is
    `$?`, which is a number."""
    quote, i = "", 0
    while i < len(cmd):
        ch = cmd[i]
        if quote == "'":
            quote = "" if ch == "'" else quote
        elif ch == "\\":
            i += 1
        elif cmd[i:i + 2] == "$?":
            i += 1
        elif ch in "$`":
            return True
        elif quote:
            quote = "" if ch == '"' else quote
        elif ch in "'\"":
            quote = ch
        elif ch in "{}*[]":
            return True
        i += 1
    return bool(quote)  # an open quote: not readable either


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
_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def _inline_heredocs(cmd: str) -> str:
    """`python3 - <<'EOF' ... EOF` as `python3 - '...'`. A here-document is text handed to the
    program, not shell: read line by line as commands, its first word of each line would be
    taken for a program and the paths it names would be lost. With an unquoted marker the shell
    still runs the $(...) inside it, so those are kept as commands."""
    def inline(m: re.Match) -> str:
        body, rest = m.group(4), m.group(3)
        runs = "" if m.group(1) else "".join(f" ; {a or b}" for a, b in _SUBSTITUTION.findall(body))
        return f" {shlex.quote(body)} {rest}{runs}"
    return _HEREDOC.sub(inline, cmd)


def read(cmd: str, cwd: str = "") -> Command:
    cmd = _inline_heredocs(cmd.replace("\0", ""))
    out = Command(cwd)
    # The hook runs in the environment Claude Code gives its commands, so a variable set there
    # has the value the command saw. Only what neither that nor the command itself sets is unknown.
    env = {**os.environ, "HOME": os.path.expanduser("~"), "PWD": cwd}
    _read(cmd, out, env, 0)
    visible = _SINGLE_QUOTED.sub("''", cmd)  # '$1' in an awk program is not a shell variable
    unset = {a or b for a, b in _VAR.findall(visible)} - set(env)
    out.dynamic = bool(_DYNAMIC.search(visible) or unset)
    return out


def _read(cmd: str, out: Command, env: dict, depth: int) -> None:
    current: list[str] = []

    def finish() -> None:
        argv = current[:]
        current.clear()
        while argv and (m := _ASSIGN.fullmatch(argv[0])):  # FOO=bar cmd, or FOO=bar on its own
            env[m.group(1)] = m.group(2)
            argv.pop(0)
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
                elif len(option) > 2 and option[0] == "-" and option[1] != "-" and (wrapper, option[1]) in _WRAPPER_CHDIR:
                    out.dirs.extend([canonical(option[2:], d) for d in out.dirs[:8]])
        if argv:
            _program(argv, fed)

    def _program(argv: list[str], fed: bool = False) -> None:
        out.programs.append(argv)
        out.program_fed.append(fed or any("$" in a for a in argv[1:]))
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
            target = next((a for a in argv[1:] if not a.startswith("-")), env["HOME"])
            out.dirs.extend([canonical(target, d) for d in out.dirs[:8]])
        if depth >= 3:
            return
        if program in _TAKES_COMMAND:
            for i, arg in enumerate(argv[1:], 1):
                # the string after -c, and for a shell any argument with spaces in it: a script
                # given as a here-document arrives that way
                if re.fullmatch(r"-\w*c", argv[i - 1]) or (program in _SHELLS and re.search(r"\s", arg)):
                    _read(arg, out, env, depth + 1)
        elif program == "eval":
            _read(" ".join(argv[1:]), out, env, depth + 1)
        elif program == "find":
            for i, arg in enumerate(argv):
                if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                    rest = argv[i + 1:]
                    end = next((j for j, a in enumerate(rest) if a in (";", "+", "\\;")), len(rest))
                    if rest[:end]:
                        _program(rest[:end])

    for token in tokens(cmd):
        if token and set(token) <= _SEPARATORS:
            finish()
        else:
            token = token.strip("`")
            current.append(_VAR.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), token))
    finish()


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
