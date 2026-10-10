"""Where a tool result came from. Content is judged by its origin, not by the tool that read it.

"external": web pages, search results, MCP tools, commands that fetch from a public address,
            files those commands saved, files under the configured external paths, and whatever
            a command or a search reads back out of those files.
"local":    files on this machine and output of local commands.
"trusted":  what WebFetch returns from an address the owner put on the trusted list: scanned and
            logged like any other, never withheld.
"own":      what one `gh` command returns about the owner's own repositories: withheld only
            from a higher score up.
"warn":     tools and programs the owner listed (warn_tools, trusted_commands): scanned and
            logged, never withheld.
None:       not scanned at all.

Nothing is exempt from blocking because of what a shell command looks like; see _own_repo.
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
_PRIVATE_SUFFIX = (".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa")

# An address that names this machine or a host on this network is not sent for scoring (unless
# scan_private_hosts), and a Monitor on one is not asked about. That is an exemption, so the
# address has to name such a host beyond doubt, to every program that might be given it. It is
# decided here and nowhere else.
#
# What went wrong before. The host was read with an expression made for the text of a shell
# command, which stops at `;` and `&`: `ws://localhost;events.example.com/` was "localhost". And
# a host with no dot in it counted as a name on the local network, though 134744072 is 8.8.8.8
# to curl and to a browser, as are 0x08080808 and 010.8.8.8 in their ways.
_ADDRESS = re.compile(r"(?:https?|wss?|ftp)://([^/?#]*)", re.I)
_AUTHORITY = re.compile(r"(?:[A-Za-z0-9._~%!$&'()*+,;=:-]*@)?"                 # user and password: what RFC 3986 allows there
                        r"(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,253})"       # a bracketed IPv6 address, or a name or IPv4 address
                        r"(?::\d{1,5})?")                                       # a port
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_NUMBER = re.compile(r"0x[0-9a-f]*|\d+")
_SCHEME = re.compile(r"\b(?:https?|wss?|ftp)://", re.I)
_URL_IN_TEXT = re.compile(r"\b(?:https?|wss?|ftp)://\S*", re.I)


def _private_ip(ip) -> bool:
    ip = getattr(ip, "ipv4_mapped", None) or ip  # ::ffff:8.8.8.8 is 8.8.8.8
    return ip.is_private or ip.is_loopback or ip.is_link_local


def private_host(host: str) -> bool:
    """host: a name, an IPv4 address or a bracketed IPv6 address, and nothing else."""
    host = host.lower()
    if host.startswith("["):
        try:
            return _private_ip(ipaddress.ip_address(host[1:-1])) if host.endswith("]") else False
        except ValueError:
            return False
    host = host[:-1] if host.endswith(".") else host
    labels = host.split(".")
    if not host or not all(_LABEL.fullmatch(label) for label in labels):
        return False
    if all(_NUMBER.fullmatch(label) for label in labels):
        # Nothing but numbers: an IP address to whatever is given it, in one of the many ways of
        # writing one (2130706433, 0x7f.1, 127.1, 010.0.0.1). Only the plain four-part form is
        # taken at its word here; the others are not taken for private.
        try:
            return _private_ip(ipaddress.IPv4Address(host))
        except ValueError:
            return False
    return host == "localhost" or len(labels) == 1 or host.endswith(_PRIVATE_SUFFIX)


def private_address(url) -> bool:
    """The address names, beyond doubt, this machine or a host on this network: a scheme, then
    nothing but an optional user part, a host and an optional port up to the first `/`, `?` or
    `#`, and that host a private one. Anything a program might read another way (a backslash, a
    semicolon in the host, a number that is an address in disguise) is not."""
    found = _ADDRESS.match(url) if isinstance(url, str) else None
    if not found or url[found.end():found.end() + 1] not in ("", "/"):
        return False  # `http://localhost#@other.example/` is localhost by the book and has not been to every program
    clean = _AUTHORITY.fullmatch(found.group(1))
    port = clean.group(0).rsplit(":", 1)[-1] if clean and re.search(r":\d+\Z", clean.group(0)) else "0"
    return bool(clean) and int(port) < 65536 and private_host(clean.group(1))


def _addresses(cmd: str) -> list[str]:
    """Every address a shell command may be handing to a program, read both ways there are of
    reading it. As the text stands: from the scheme to the next space, without a quote, bracket
    or semicolon that closes it. And as the shell would hand it over: an argument that is an
    address is that whole argument, whatever is in it (`'http://local host/'`,
    `http://local"host.example.com"/`). A command is taken to stay on this machine or network
    only if every one of these is private."""
    found = [m.group(0).rstrip("'\");,") for m in _URL_IN_TEXT.finditer(cmd)]
    try:
        for argv in shell.read(cmd, "").programs:
            for arg in argv:
                if _SCHEME.match(arg):
                    found.append(arg)  # an argument that is an address: all of it, spaces and quotes and all
                else:
                    found += [m.group(0).rstrip("'\");,") for m in _URL_IN_TEXT.finditer(arg)]
    except Exception:
        pass  # the text has been read; a command the reader cannot take apart is not assumed local elsewhere
    return found


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


def fetches_outside(cmd: str, scan_private_hosts: bool = False) -> bool:
    """The command reads from a public address: a literal URL of a public host, or a tool that
    only talks to a remote service. A fetch whose address is not visible in the command (a
    variable, a script) counts as local: its output may be private data from this network."""
    # A `;` may end the command or, inside quotes, belong to the address; a quote may close the
    # address or splice two halves of a host together. An address that is private on one reading
    # only is not taken for private.
    if any(scan_private_hosts or not private_address(u) for u in _addresses(cmd)):
        return True
    return bool(_REMOTE_TOOL.search(cmd))


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


# ---- the two things a shell command can still be given ----------------------------------------------
# No shell command is exempt from blocking because of what it looks like. Earlier versions read
# a command to prove that its output came from a trusted address, was the echo of the agent's
# own write, or only reported on the agent's own work, and each of those proofs was broken
# through something the shell or the program does that the reader did not model: a glob, a
# redirection, `cd`, PATH, curl's write-out, the commit titles git prints. What is left rests on
# shell.literal_command, which follows nothing, and gives no exemption:
#
# - one `gh` command that names an own repository is withheld from a higher score up ("own");
# - one program the owner listed in trusted_commands is scanned and not withheld ("warn"): the
#   owner's own word for that program, not the guard's reading of it.

def _search_path_fixed() -> bool:
    """Every entry of PATH is absolute, so a bare name means the same program whatever the
    directory. Which program that is, is the owner's setup and not judged here."""
    return all(os.path.isabs(entry) for entry in os.environ.get("PATH", "").split(":"))


def trusted_command(cmd: str, extra: set) -> bool:
    """The command is one program from the owner's trusted_commands with literal arguments."""
    argv = shell.literal_command(cmd)
    return bool(argv) and argv[0] in extra and _search_path_fixed()


def _own_repo(cmd: str, cfg) -> bool:
    """The command is one `gh` invocation, written out literally, about nothing but the owner's
    own repositories. Not an exemption: the result is scanned, withheld from own_repos_block up
    and withheld when the scan fails and on_error is closed. Anything beside that one program
    (a pipe, a second command, a redirection, `cd`) and the command is ordinary outside content;
    so is a repository taken from the directory instead of named, an address among the
    arguments, another host, or gh set up to send its requests somewhere else."""
    from . import github
    argv = shell.literal_command(cmd)
    if argv and argv[:2] == ["rtk", "gh"]:
        argv = argv[1:]  # gh run through the output filter of this setup
    if not argv or argv[0] != "gh" or not _search_path_fixed():
        return False
    if any("://" in a for a in argv):
        return False  # a pull request or an issue given by its address is wherever that address is
    if os.environ.get("GH_HOST") or os.environ.get("GH_REPO") or github.rerouted():
        return False
    repos = github.gh_repos(argv)
    return bool(repos) and all(github.is_own(r, cfg.own_repos) for r in repos)


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
            if private_address(url) and not cfg.scan_private_hosts:
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
            # The trusted list does not reach here: it holds for WebFetch, where the address is a
            # field of the call. What a shell command really fetches cannot be read off it.
            return "own" if cfg.own_repos and _own_repo(cmd, cfg) else "external"
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
