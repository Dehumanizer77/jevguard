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

# Commands whose output only reports on the agent's own work. Every segment of a compound
# command must be one of these; command substitution never is. ls is not here: file names can
# come from outside.
_TRUSTED_CMDS = {"cd", "pwd", "echo", "printf", "which", "whoami", "id", "hostname", "date", "uptime",
                 "df", "du", "wc", "mkdir", "touch", "cp", "mv", "rm", "ln", "chmod", "true", "sleep"}
_TRUSTED_GIT = {"status", "add", "commit", "checkout", "switch", "branch", "stash", "rev-parse", "init",
                "restore", "tag"}

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


def trusted_command(cmd: str, extra: set) -> bool:
    if not cmd.strip() or re.search(r"\$\(|`|<\(", cmd):
        return False
    cmd = re.sub(r"\d*>&\d+", " ", cmd)  # 2>&1 is a redirect, not a background job
    for seg in re.split(r"&&|\|\||[;|&\n]", cmd):
        words = seg.split()
        while words and re.fullmatch(r"\w+=\S*", words[0]):  # FOO=bar cmd
            words.pop(0)
        if words and words[0] == "rtk":
            words.pop(0)
        if not words:
            continue
        name = os.path.basename(words[0])
        if name == "git":
            sub = next((w for w in words[1:] if not w.startswith("-")), "")
            if sub not in _TRUSTED_GIT:
                return False
        elif name not in _TRUSTED_CMDS and name not in extra:
            return False
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
_FD = re.compile(r"(?<= )\d(?=>)")         # the 2 of 2>/dev/null
_SED_PRINT = re.compile(r"\d+(?:,\d+)?p")  # sed -n '1,80p', and nothing else of sed
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
    """The simple commands of a command line, each as its words without redirections and without
    a leading `rtk`. None when the line is not written out in full: a here-document, anything
    the shell still expands, or a control character. A line break inside a quoted argument
    reaches the program as part of that argument, and in a header it starts a second header; a
    line break outside quotes starts another command. Neither is taken apart here."""
    cmd = cmd.strip()
    if "<<" in cmd or _CONTROL.search(cmd) or shell.expands(cmd):
        return None
    commands = []
    for words in shell.simple_commands(_FD.sub("", cmd)):
        words = shell.without_redirections(words[1:] if words[0] == "rtk" else words)
        if words:
            commands.append(words)
    return commands


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
    the output or anything about the command is not plain: a program beside `gh` that is not a
    filter on its input (curl with a config file, a script, cat of a file), a repository that
    cannot be told, a value computed at run time, another host."""
    from . import github
    commands = _plain_commands(cmd)
    if commands is None or os.environ.get("GH_HOST") or os.environ.get("GH_REPO") or github.rerouted():
        return None
    if not all(words[0] == "gh" or _adds_nothing(words[0], words[1:]) for words in commands):
        return None
    try:
        c = shell.read(cmd, cwd)
    except Exception:
        return None
    calls = [words for words in commands if words[0] == "gh"]
    places = [dirs for argv, dirs in zip(c.programs, c.program_dirs) if argv[0] == "gh"]  # after any `cd`
    if not calls or len(places) != len(calls):
        return None
    for argv, dirs in zip(calls, places):
        repos = github.gh_repos(argv, dirs)
        if not repos or not all(github.is_own(r, cfg.own_repos) for r in repos):
            return None
    return "echo" if all(github.gh_echo(argv) for argv in calls) else "own"


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
            elif name == "header" and not _plain_header(value):
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
                if c == "H" and not _plain_header(value):
                    return None
                break
    return urls


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
        return "warn" if trusted_command(cmd, set(cfg.trusted_commands)) else "local"
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
