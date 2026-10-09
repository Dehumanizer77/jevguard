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
# Programs that only run another program: the command after them is what counts.
_WRAPPERS = {"rtk", "sudo", "doas", "env", "time", "nohup", "command", "builtin", "exec", "nice", "ionice",
             "stdbuf", "setsid", "timeout", "xargs", "watch"}
# Programs that take a command line as the string after -c (bash -lc '...', script -qc '...').
_TAKES_COMMAND = {"bash", "sh", "zsh", "dash", "ksh", "su", "script"}
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


class Command:
    def __init__(self, cwd: str = ""):
        self.programs: list[list[str]] = []  # argv of each simple command, wrappers removed
        self.program_dirs: list[list[str]] = []  # for each program, the directories it may be running in
        self.program_paths: list[set[str]] = []  # for each program, the paths its arguments name
        self.program_globs: list[list[str]] = []  # and the glob patterns
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


def read(cmd: str, cwd: str = "") -> Command:
    cmd = cmd.replace("\0", "")
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
        while argv and os.path.basename(argv[0]) in _WRAPPERS:
            argv.pop(0)
            while argv and (argv[0].startswith("-") or argv[0].replace(".", "").isdigit()
                            or argv[0] == "{}" or _ASSIGN.fullmatch(argv[0])):
                argv.pop(0)
        if argv:
            _program(argv)

    def _program(argv: list[str]) -> None:
        out.programs.append(argv)
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
            for i, arg in enumerate(argv[1:-1], 1):
                if re.fullmatch(r"-\w*c", arg):
                    _read(argv[i + 1], out, env, depth + 1)
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
    if arg.startswith("-"):
        if "=" not in arg:
            return
        arg = arg.split("=", 1)[1]
    if arg and len(arg) <= 300 and not re.search(r"[\s'\"();]", arg):
        candidates = expand_braces(arg)
    else:
        candidates = _EMBEDDED.findall(arg[:20000])
    for cand in candidates:
        if _GLOB.search(cand):
            expanded = os.path.expanduser(cand)
            for d in [""] if os.path.isabs(expanded) else dirs:
                globs.append(os.path.normpath(os.path.join(d, expanded)))
        else:
            paths.update(resolve(cand, dirs))
