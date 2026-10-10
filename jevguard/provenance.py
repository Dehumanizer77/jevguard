"""Where a tool result came from. Content is judged by its origin, not by the tool that read it.

"external": web pages, search results, MCP tools, commands that fetch from a public address,
            files those commands saved, files under the configured external paths, and whatever
            a command or a search reads back out of those files.
"local":    files on this machine and output of local commands.
"trusted":  outside content from an address the owner put on the trusted list: scanned and
            logged like any other, never withheld.
"own":      what `gh` returns about the owner's own repositories: withheld only from a higher
            score up. "echo": the reply to something the command itself just created there;
            never withheld.
"warn":   output of commands that only report on the agent's own work; never blocked.
None:       not scanned at all.
"""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlsplit

from . import shell, store
from .shell import canonical, under

# Commands that only ever talk to a remote service.
_REMOTE_TOOL = re.compile(r"(?:^|[\s;|&(])(?:rtk\s+)?(?:gh|himalaya|yt-dlp|lynx|w3m|notmuch)\b")
_URL = re.compile(r"\b(?:https?|wss?|ftp)://([^\s/'\"<>|;&)\\]+)", re.I)
_PRIVATE_SUFFIX = (".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa")

# Commands whose output only reports on the agent's own work; it is scanned and never withheld.
# Every program in the command has to be one of these, by its bare name, in a form that prints
# nothing else (see trusted_command). ls is not here: file names can come from outside.
_TRUSTED_CMDS = {"cd", "pwd", "echo", "printf", "which", "whoami", "id", "hostname", "date", "uptime",
                 "df", "du", "wc", "mkdir", "touch", "cp", "mv", "rm", "ln", "chmod", "true", "sleep"}
# Three of them can be handed a file of names or dates and then complain about every line of it:
# (letters of such options, their long names).
_LIST_OPTIONS = {"date": ("f", ("--file",)), "wc": ("", ("--files0-from",)), "du": ("", ("--files0-from",))}
# git subcommands of the same kind, each with the options that make it print something else: a
# patch, the staged changes, the text of a commit someone else wrote. None: any arguments.
# stash and a plain checkout are not here: both print the title of a commit, whoever wrote it.
_GIT_ALWAYS = ("piev", ("--patch", "--interactive", "--edit", "--verbose", "--format", "--pretty"))
_GIT_REPORTS = {
    "status": ("", ()), "add": ("", ()), "restore": ("", ()), "rev-parse": None, "init": None,
    # a message that is not written in the command comes back in the summary line
    "commit": ("FCct", ("--file", "--fixup", "--squash", "--reuse-message", "--reedit-message", "--template",
                        "--amend", "--dry-run")),
    "switch": ("d", ("--detach",)),
    "checkout": ("", ()),  # as `checkout -b` only
    "branch": ("ra", ("--remotes", "--all", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at")),
    "tag": ("n", ()),
}


def private_host(host: str) -> bool:
    host = host.rsplit("@", 1)[-1].lower()
    if host.startswith("["):  # [::1]:8080
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or "." not in host or host.endswith(_PRIVATE_SUFFIX)


_URL_FULL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>|;&)\\]+", re.I)
_DEFAULT_PORT = {"http": 80, "https": 443}


def _url_parts(url: str):
    """(scheme, host, port, path) of an http(s) address, or None for anything else or anything
    that does not parse cleanly: a backslash, a password part, an odd port. Those are how one
    address is made to look like another, and an address on the trusted list is not scored
    for blocking, so a doubtful one is simply not trusted."""
    if any(ord(c) < 33 or c in "\\{}[]*$`^|<>\"'" for c in url):
        return None  # also what a shell or curl would expand into a second address: {a,b}, [1-3]
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    scheme = u.scheme.lower()
    if scheme not in _DEFAULT_PORT or not u.hostname or u.username is not None or u.password is not None:
        return None
    return scheme, u.hostname.lower().rstrip("."), port or _DEFAULT_PORT[scheme], u.path or "/"


def trusted_source(url: str, prefixes: list) -> bool:
    """The address lies under one of the trusted prefixes: same scheme, same host, same port, and
    its path is the prefix's path or below it. `https://docs.example.com/guide` covers
    `/guide` and `/guide/x`, not `/guide-2`, not `docs.example.com.evil.net`, not
    `docs.example.com@evil.net`."""
    target = _url_parts(url)
    if not target or not _plain_path(target[3]):
        return False
    for prefix in prefixes:
        base = _url_parts(str(prefix))
        if not base or base[:3] != target[:3] or not _plain_path(base[3]):
            continue
        root = base[3].rstrip("/")
        if target[3] == root or target[3].startswith(root + "/"):
            return True
    return False


def _plain_path(path: str) -> bool:
    """A path that means the same to every server that might receive it. No percent escape
    anywhere: `%2e%2e` and `%2f` are dots and slashes to whatever decodes them, and a server may
    decode twice. No parameter (`..;/` climbs on some servers), no empty segment, no segment that
    starts with two dots. An address that needs any of these is fetched as ordinary outside
    content; nothing is lost but the exemption."""
    if "%" in path or ";" in path:
        return False
    segments = path.split("/")[1:]
    return not any(s in ("", ".") or s.startswith("..") for s in segments[:-1]) and \
        not segments[-1].startswith("..") and segments[-1] != "."


def fetched_urls(cmd: str) -> list[str]:
    return [u.rstrip(".,") for u in _URL_FULL.findall(cmd)]


def fetches_outside(cmd: str, scan_private_hosts: bool = False) -> bool:
    """The command reads from a public address: a literal URL of a public host, or a tool that
    only talks to a remote service. A fetch whose address is not visible in the command (a
    variable, a script) counts as local: its output may be private data from this network."""
    hosts = _URL.findall(cmd)
    if any(scan_private_hosts or not private_host(h) for h in hosts):
        return True
    return bool(_REMOTE_TOOL.search(cmd))


def _uses(args: list[str], letters: str, longs: tuple) -> bool:
    """One of the arguments is one of these options: a short one alone or in a run (-av), a long
    one in full or cut short the way these programs accept it (--verb). An option's value that
    happens to look like one counts too; that costs the exemption and nothing else."""
    for a in args:
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if len(name) > 2 and any(full.startswith(name) or name.startswith(full) for full in longs):
                return True
        elif a.startswith("-") and any(c in letters for c in a[1:]):
            return True
    return False


def _git_reports(words: list[str]) -> bool:
    """`git status`, `git add`, `git commit -m ...` and the like, in a form that only reports on
    the agent's own work. Only with the subcommand as the first argument: `git -c name=value` can
    make git run a program, and `git -C elsewhere` works in another checkout."""
    args = words[2:] if words[1:2] == ["--no-pager"] else words[1:]
    if words[0] != "git" or not args or args[0] not in _GIT_REPORTS:
        return False
    rule = _GIT_REPORTS[args[0]]
    if rule is None:
        return True
    if args[0] == "checkout" and args[1:2] not in (["-b"], ["-B"]):
        return False  # any other form may leave a branch: "HEAD is now at <title of that commit>"
    return not _uses(args[1:], _GIT_ALWAYS[0] + rule[0], _GIT_ALWAYS[1] + rule[1])


def _names_a_device(arg: str, dirs: list[str]) -> bool:
    """The argument is, holds or leads to something under /dev or /proc. A file copied or moved
    there is printed: /dev/stdout, /proc/self/fd/1, or a link to one of them under any name."""
    forms = {arg, arg.partition("=")[2], arg[2:] if arg.startswith("-") and not arg.startswith("--") else ""}
    for form in filter(None, forms):
        for base in dirs or [""]:
            path = os.path.join(base, os.path.expanduser(form))
            for _ in range(16):
                head, tail = os.path.split(path.rstrip("/") or "/")
                dotted = tail in ("", ".", "..")
                path = os.path.realpath(path) if dotted else os.path.join(os.path.realpath(head or "."), tail)
                if path != "/dev/null" and (under(path, "/dev") or under(path, "/proc")):
                    return True
                try:
                    path = os.path.join(os.path.dirname(path), os.readlink(path))
                except OSError:
                    break
            else:
                return True  # a chain of links this long is not followed to its end
    return False


def trusted_command(cmd: str, extra: set, cwd: str = "") -> bool:
    """Every program in the command only reports on the agent's own work, and stands in a form
    that prints nothing else. The command has to run as written (see _plain_commands):
    `echo $(cat notes.txt)`, `echo *` and `wc -l < notes.txt` print other things. Programs count
    by their bare name: ./date and /tmp/tools/cp are other programs, and `PATH=... date` may be."""
    commands = _plain_commands(cmd)
    if not commands:
        return False
    dirs = [canonical(cwd)] if cwd else []
    for words in commands:
        name, args = words[0], words[1:]
        if name == "git":
            if not _git_reports(words):
                return False
        elif name not in _TRUSTED_CMDS and name not in extra:
            return False
        elif name in _LIST_OPTIONS and _uses(args, *_LIST_OPTIONS[name]):
            return False
        if any(_names_a_device(a, dirs) for a in args):
            return False
        if name == "cd":
            dirs = dirs + [canonical(a, d) for a in args[:1] if not a.startswith("-") for d in dirs[:8]]
    return True


def saved_paths(cmd: str, cwd: str, track_clones: bool) -> list[str]:
    """Files written by a command that fetches from outside or reads an outside file: reading
    them later is reading outside content (see shell.written_paths for what is recognised).
    Not followed: an archive unpacked into the current directory, a name chosen by the server,
    and files a script writes on its own."""
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return []
    # A destination that is the working directory or above it would make the whole project
    # outside content on the strength of one command; that is not what the command says.
    return sorted(p for p in shell.written_paths(c, track_clones)
                  if not p.startswith("/dev/") and not any(under(d, p) for d in c.dirs))


def _matches(tool: str, patterns: list) -> bool:
    return any(re.fullmatch(p, tool) for p in patterns)


def outside_roots(cfg, session_paths: list[str]) -> list[str]:
    """Everything whose content counts as coming from outside: the configured directories, the
    quarantined originals and what this session downloaded. The rest of the guard's state (its
    log, counters, session records) holds no content from outside."""
    # The files in the released directory are on the list as well. Being there exempts nothing:
    # only a file the release command wrote is exempt, only while unchanged, and only when read
    # with Read (store.released_artifact). Listed one by one, not as a directory, so that a text
    # which merely names the directory (the README does) is not taken for its content.
    return ([canonical(p) for p in cfg.external_paths] + [canonical(str(cfg.quarantine_dir))]
            + _released_files(cfg) + list(session_paths))


def _released_files(cfg) -> list[str]:
    folder = canonical(str(cfg.released_dir))
    try:
        return [os.path.join(folder, name) for name in sorted(os.listdir(folder))[-500:]]
    except OSError:
        return []


def mentions(text: str, roots: list[str], bases: list[str]) -> bool:
    """The text names an outside file or directory: by absolute path, or by its path relative to
    one of the bases (a search prints `sub/page.html:12:...` for what it found there)."""
    if not text:
        return False
    home = os.path.expanduser("~")
    for root in roots:
        # A directory counts when something inside it is named; its bare name in a listing does not.
        is_dir, is_file = os.path.isdir(root), os.path.isfile(root)
        tail = "/" if is_dir else ""
        if root + tail in text or (under(root, home) and root != home and "~" + root[len(home):] + tail in text):
            return True
        for base in bases:
            if not (base and root != base and under(root, base)):
                continue
            rel = root[len(base.rstrip("/")) + 1:]
            if rel not in text:
                continue
            # A relative name counts only where a listing or a search would print it: at the start
            # of a line, as `name:12:...`, `name-12-...`, `name/inside` or on a line of its own.
            # The same word in the middle of a sentence ("on branch main") is not that file.
            name = r"(?m)^\s*(?:\./)?" + re.escape(rel)
            as_file = re.search(name + r"(?:[:-]|\s*$)", text) if not is_dir else None
            as_dir = re.search(name + "/", text) if not is_file else None
            if as_file or as_dir:
                return True
    return False


_file_name = re.compile(r"[\w@%+-][\w@%+.-]{2,}\.[A-Za-z0-9]{1,8}")  # page.html, data-2.json; not "main" or "out"


def _bash_reads_outside(cmd: str, cwd: str, roots: list[str], session_paths: list[str], output: str,
                        folders: list[str] = ()) -> bool:
    """The command, as far as it can be read, takes its output from an outside file: it runs in an
    outside directory, names an outside file (directly, relatively, after `cd`, through a variable
    it set, by glob, or inside a quoted script), or prints one's name among its results. When the
    session has downloaded files and the command picks its files at run time, it counts too.
    folders count when the command names them or works in them, not when its output does."""
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return True  # a command that cannot be read is not assumed to be local
    if any(c.names(r) for r in [*roots, *folders]):
        return True
    if any(_file_name.fullmatch(os.path.basename(p)) and os.path.basename(p) in cmd for p in session_paths):
        return True  # named in a way the reader did not resolve; only for names that read as a file's
    if session_paths and c.dynamic:
        return True
    return mentions(output, roots, c.dirs)


# ---- commands written out in full -------------------------------------------------------------------
# The exemptions below (the owner's own repositories, a trusted address) hold for a command only
# when everything that can add to its output is accounted for. That is decided on the command as
# written, so it has to be written out in full, and every program in it has to be known.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SOCKET = re.compile(r"/dev/+(?:tcp|udp)(?:/|$)")  # bash opens a connection for such a redirection
_SED_PRINT = re.compile(r"\d+(?:,\d+)?p")  # sed -n '1,80p', and nothing else of sed
_JQ_READS = re.compile(r"\b(?:import|include|modulemeta)\b")
_DIGITS = "0123456789"
# Filters as they stand at the end of a pipe: (flag letters, letters of options that take a
# value, how many other arguments). Only forms that read nothing but their input: a file operand
# (`head notes.txt`, `cat - notes.txt`, `grep -r x`, `jq -f prog`) would put that file into
# output that is then not withheld. awk and a sed script can run other programs.
_GREP = ("inovEFPcqsxwhH" + _DIGITS, "mABC", 1)
_STDIN_FILTERS = {"head": ("qv" + _DIGITS, "nc", 0), "tail": ("qv" + _DIGITS, "nc", 0), "grep": _GREP, "egrep": _GREP,
                  "fgrep": _GREP, "jq": ("rcesSMCanj", "", 1), "wc": ("lwcmL", "", 0), "cat": ("AbEnsTv", "", 0),
                  "sort": ("bdfghinMRrVsu", "kt", 0), "uniq": ("cdiu", "fsw", 0), "cut": ("s", "dfcb", 0),
                  "tr": ("cdst", "", 2)}
# Programs that print their own arguments, pass their input on, or print nothing.
_NO_CONTENT = {"cd", "echo", "printf", "true", "tee"}


def _plain_commands(cmd: str) -> list[list[str]] | None:
    """The simple commands of a command line, each as its words, without a leading `rtk`. None
    when the line is not written out in full, or takes something in by a side door:

    - anything the shell still expands, a comment, an open quote;
    - a control character. A line break inside a quoted argument reaches the program as part of
      that argument, and in a header it starts a second header;
    - a redirection that supplies input. `cat < /dev/tcp/host/port` reads from the network and
      `head < notes.txt` from a file, whatever the program is taken for; a here-document, `<&3`
      and `<>` likewise;
    - a redirection to a /dev/tcp or /dev/udp address, in either direction.

    Output redirections bring nothing in and are left out. What is an operator and what is an
    argument is decided by quoting (shell.plain_commands): `'>'` is an argument, and so is the
    word after it."""
    cmd = cmd.strip()
    commands = None if _CONTROL.search(cmd) else shell.plain_commands(cmd)
    if commands is None:
        return None
    plain = []
    for words, redirections in commands:
        if any("<" in operator or _SOCKET.search(target) for operator, target in redirections):
            return None
        # `rtk curl` is curl run through the output filter of this setup. Only before the programs
        # that fetch: what rtk makes of `grep` or `head` is not known here.
        if words[:1] == ["rtk"] and words[1:2] and words[1] in ("curl", "wget", "gh", "git"):
            words = words[1:]
        if words:
            plain.append(words)
    return plain


def _adds_nothing(name: str, args: list[str]) -> bool:
    """The program brings no content of its own into the output: it filters what it is piped, or
    prints only its arguments. By bare name: ./grep and /tmp/grep are other programs."""
    if name in _NO_CONTENT:
        return True
    if name == "sed":
        return len(args) == 2 and args[0] == "-n" and bool(_SED_PRINT.fullmatch(args[1]))
    if name not in _STDIN_FILTERS:
        return False
    flags, values, operands = _STDIN_FILTERS[name]
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-"):
            operands -= 1
            if name == "jq" and _JQ_READS.search(a):
                return False  # import "notes" as $n: a jq program can load a file of its own
        elif len(a) < 2 or a.startswith("--"):
            return False  # `-`, and long options: --files0-from and the like read files
        else:
            for j, c in enumerate(a[1:], 1):
                if c in values:
                    if not a[j + 1:]:
                        i += 1  # its value is the next word
                    break
                if c not in flags:
                    return False
    return operands >= 0 and i <= len(args)


def _own_repo_mode(cmd: str, cwd: str, cfg) -> str | None:
    """"own" when everything the command prints is `gh` output about the owner's own
    repositories; "echo" when all of it is the reply to something the command itself just created
    there (gh pr create, a comment posted through gh api). None when anything else could add to
    the output or anything about the command is not plain: a program beside `gh` that is neither
    a filter on its input nor plain git (curl with a config file, a script, cat of a file), a
    repository that cannot be told, a value computed at run time, another host. A `git push`
    to an own repository beside `gh` keeps the result "own"."""
    from . import github
    commands = _plain_commands(cmd)
    if commands is None or os.environ.get("GH_HOST") or os.environ.get("GH_REPO") or github.rerouted():
        return None
    remote = []  # the commands that bring something back from a server (gh, git push), and where they run
    dirs = [canonical(cwd)] if cwd else []
    for words in commands:
        name, args = words[0], words[1:]
        if name == "cd":
            if len(args) > 1 or any(a.startswith("-") for a in args):
                return None  # `cd -`: where that leads is not in the command
            # the old directories stay on the list: a `cd` that fails, or sits in a pipe, moves nothing
            dirs = dirs + [canonical(args[0] if args else "~", d) for d in dirs[:8]]
        elif name == "gh" or words[:2] == ["git", "push"]:
            remote.append((words, list(dirs)))
        elif not _adds_nothing(name, args) and not _git_reports(words):
            return None
    if not any(words[0] == "gh" for words, _ in remote):
        return None
    echo = True
    for words, dirs in remote:
        if words[0] == "gh":
            repos = github.gh_repos(words, dirs)
            echo = echo and github.gh_echo(words)
            # A reply that carries a local file back is local content as much as own-repository
            # output; it is never given the more lenient of the two levels.
            if github.gh_sends_file(words) and cfg.scan_local and cfg.local_block < cfg.own_repos_block:
                return None
        else:
            # What the server says to a push is not something the command sent: no echo. It counts
            # as about an own repository only when the push plainly goes to one.
            repos, echo = github.push_repos(words[2:], dirs), False
        if not repos or not all(github.is_own(r, cfg.own_repos) for r in repos):
            return None
    return "echo" if echo else "own"


# ---- a fetch that is plainly from a trusted address -------------------------------------------------
# The options a plain download uses: (short flags, short options with a value, long flags, long
# options with a value). Anything else (a proxy, --resolve, --connect-to, a config file, -k) can
# make a trusted address return someone else's content, so a command using it is handled as
# ordinary outside content.
_CURL = (set("sSLfiIvgO46"), set("omAHwe"),
         {"silent", "show-error", "location", "fail", "fail-with-body", "include", "head", "verbose", "compressed",
          "ipv4", "ipv6", "remote-name", "globoff", "no-progress-meter", "tlsv1.2", "tlsv1.3"},
         {"output", "output-dir", "max-time", "connect-timeout", "retry", "retry-delay", "retry-max-time",
          "user-agent", "header", "write-out", "referer", "url", "proto"})
_WGET = (set("qSc"), set("OPTtU"),
         {"quiet", "no-verbose", "server-response", "continue"},
         {"output-document", "directory-prefix", "timeout", "tries", "user-agent", "header"})
# Request headers that do not choose whose content comes back. Host does, and so can a
# forwarding header on a server that honours it.
_HEADERS = {"accept", "accept-language", "accept-encoding", "user-agent", "cache-control", "pragma",
            "if-none-match", "if-modified-since", "referer", "authorization", "x-github-api-version"}


def _plain_header(value: str) -> bool:
    """One header with an allowed name. `@file` and `Host;` have no such name, and a value with
    a line break in it is two headers: `Accept: x\\r\\nX-Forwarded-Host: elsewhere`."""
    name, colon, _ = value.partition(":")
    return bool(colon) and not _CONTROL.search(value) and name.strip().lower() in _HEADERS


def _plain_download(args: list[str], spec: tuple) -> list[str] | None:
    """The addresses one curl or wget invocation fetches, or None when it uses anything outside
    the plain set."""
    flags, values, long_flags, long_values = spec
    if any(_CONTROL.search(a) for a in args):
        return None  # a user agent or a referer with a line break in it carries a header of its own
    urls, i = [], 0
    while i < len(args):
        a = args[i]
        i += 1
        if not a.startswith("-") or a == "-":
            urls.append(a)
        elif a.startswith("--"):
            name, eq, value = a[2:].partition("=")
            if name in long_flags and not eq:
                continue
            if name not in long_values:
                return None
            if not eq:
                if i >= len(args):
                    return None
                value = args[i]
                i += 1
            if name == "url":
                urls.append(value)
            elif not _plain_value(name, value):
                return None
        elif a == "-nv" and spec is _WGET:
            continue
        else:
            for j, c in enumerate(a[1:], 1):
                if c in flags:
                    continue
                if c not in values:
                    return None
                value = a[j + 1:]
                if not value:
                    if i >= len(args):
                        return None
                    value = args[i]
                    i += 1
                if not _plain_value(c, value):
                    return None
                break
    return urls


def _plain_value(option: str, value: str) -> bool:
    if option in ("H", "header"):
        return _plain_header(value)
    if option in ("w", "write-out"):
        return not value.startswith("@")  # curl -w @notes.txt prints that file
    return True


def _own_settings(program: str) -> bool:
    """A settings file that curl or wget reads on its own exists. It can name a proxy or further
    addresses, nothing in the command shows it, and the guard cannot tell who wrote it."""
    env, home = os.environ, os.path.expanduser("~")
    if program == "wget":
        places = [env.get("WGETRC"), os.path.join(home, ".wgetrc")]
    else:
        places = [env.get("CURL_HOME") and os.path.join(env["CURL_HOME"], ".curlrc"),
                  env.get("XDG_CONFIG_HOME") and os.path.join(env["XDG_CONFIG_HOME"], "curlrc"),
                  os.path.join(home, ".curlrc"), os.path.join(home, ".config", "curlrc")]
    return any(p and os.path.exists(p) for p in places)


def _trusted_fetch(cmd: str, cfg) -> bool:
    """The command is nothing but plain curl or wget downloads from addresses on the trusted list,
    and filters. Trust is read off what is fetched: an address printed by echo, left in a comment
    or kept in a config file proves nothing, and neither does a command the shell still has to
    put together or one that runs anything else beside the download."""
    commands = _plain_commands(cmd) if cfg.trusted_sources else None
    if not commands:
        return False
    programs = set()
    for words in commands:
        name, args = words[0], words[1:]  # the bare name only: ./curl and /tmp/curl are other programs
        if name in ("curl", "wget"):
            urls = _plain_download(args, _CURL if name == "curl" else _WGET)
            if not urls or not all(trusted_source(u, cfg.trusted_sources) for u in urls):
                return False
            programs.add(name)
        elif not _adds_nothing(name, args):
            return False
    return bool(programs) and not any(_own_settings(p) for p in programs)


def _has_option(args: list[str], letter: str, long: str, value_letters: set) -> bool:
    for a in args:
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if len(name) >= 6 and long.startswith(name):  # --conf is --config to the program too
                return True
        elif a.startswith("-"):
            for c in a[1:]:
                if c == letter:
                    return True
                if c in value_letters:
                    break
    return False


def _hidden_fetch(cmd: str, cwd: str) -> bool:
    """curl or wget told to take its addresses from a file. Where it fetches from cannot be seen,
    so the result is outside content. A variable in the address is another matter: that is
    usually a service on this network (see fetches_outside)."""
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return False
    for argv in c.programs:
        name, args = os.path.basename(argv[0]), argv[1:]
        if name == "curl" and _has_option(args, "K", "--config", shell._CURL_VALUE_OPTS):
            return True
        if name == "wget" and _has_option(args, "i", "--input-file", shell._WGET_VALUE_OPTS):
            return True
    return False


def _public_urls(cmd: str, cfg) -> list[str]:
    hosts = [(u, _URL.match(u)) for u in fetched_urls(cmd)]
    return [u for u, m in hosts if m and (cfg.scan_private_hosts or not private_host(m.group(1)))]


def classify(tool: str, tool_input: dict, cfg, cwd: str, session_paths: list[str], output: str = "") -> str | None:
    """output is the text of the result: a search over local directories that returns lines from
    an outside file is outside content, and only the result shows that."""
    if _matches(tool, cfg.skip_tools):
        return None
    if _matches(tool, cfg.warn_tools):
        return "warn"
    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        if tool == "WebFetch":
            url = str(tool_input.get("url") or "")
            m = _URL.match(url)
            if m and private_host(m.group(1)) and not cfg.scan_private_hosts:
                return "local"
            if trusted_source(url, cfg.trusted_sources):
                return "trusted"
        return "external"
    roots = outside_roots(cfg, session_paths)
    released = canonical(str(cfg.released_dir))
    if tool == "Bash":
        cmd = str(tool_input.get("command") or "")
        if _bash_reads_outside(cmd, cwd, roots, session_paths, output, [released]):
            return "external"
        if fetches_outside(cmd, cfg.scan_private_hosts) or _hidden_fetch(cmd, cwd):
            # Trusted only if every public address the text of the command holds is on the list,
            # and the command is nothing but a plain download of those addresses.
            public = _public_urls(cmd, cfg)
            if public and all(trusted_source(u, cfg.trusted_sources) for u in public) and _trusted_fetch(cmd, cfg):
                return "trusted"
            if not public and cfg.own_repos:
                return _own_repo_mode(cmd, cwd, cfg) or "external"
            return "external"
        return "warn" if trusted_command(cmd, set(cfg.trusted_commands), cwd) else "local"
    if tool in ("Read", "Grep"):
        base = canonical(cwd) if cwd else ""
        path = canonical(str(tool_input.get("file_path") or tool_input.get("path") or cwd or "/"), cwd)
        if tool == "Read" and store.released_artifact(cfg, path):
            return None  # an original the owner read and released, unchanged: not scanned a second time
        if any(under(path, r) for r in [*roots, released]):
            return "external"
        if tool == "Grep" and mentions(output, roots, [path, base]):
            return "external"
        return "local"
    return None  # tools that carry no outside content, and tools this list does not know
