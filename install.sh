#!/bin/bash
# install.sh: install jevguard for the system, or update such an installation. Run as root,
# from a clone only root can write:
#
#   sudo sh -c 'umask 022 && git clone https://github.com/Dehumanizer77/jevguard /opt/jevguard'
#   sudo bash /opt/jevguard/install.sh             install, and later: update to the newest main
#   bash /opt/jevguard/install.sh --dry-run        say what it would do, and do nothing
#
# Not from a copy in a home directory: the agent runs as that user, and could change the script
# between the download and sudo. Run from such a place, it refuses.
#
# It puts the code in /opt/jevguard (a clone only root can write), runs
# `jevguard setup-system` for the user the agents run as (the one who ran sudo), asks for the
# API key when there is none yet, and checks the result. What setup-system does is in
# docs/REFERENCE.md, "System installation". It deletes nothing: the old copies in the user's
# home it names, for the user to remove once the installation works.
set -euo pipefail
umask 022

repo=https://github.com/Dehumanizer77/jevguard
dir=/opt/jevguard
ref=main
owner=${SUDO_USER:-}
agents=()
dry=false
selftest=true

usage() {
    cat <<'JEVGUARD_USAGE_END'
usage: sudo bash install.sh [--user NAME] [--agent claude|codex]... [--ref REF] [--dir DIR]
                            [--no-selftest] [--dry-run]

  --user NAME    the user the agents run as (default: the one who ran sudo)
  --agent NAME   an agent to install for: claude, codex; may be given twice
                 (default: claude, and codex when NAME has a ~/.codex)
  --ref REF      the branch, tag or commit to install (default: main)
  --dir DIR      where the code goes (default: /opt/jevguard)
  --no-selftest  do not send the two test samples to the scoring API at the end
  --dry-run      say what would be done, and do nothing
JEVGUARD_USAGE_END
}

die() { echo "install.sh: $*" >&2; exit 1; }

# All of it in one function, read whole before it runs: updating the clone may replace this
# very file while it runs.
main() {
while [ $# -gt 0 ]; do
    case "$1" in
        --user) owner=${2:?--user needs a name}; shift 2 ;;
        --agent) case "${2:-}" in claude|codex) agents+=("$2") ;; *) die "--agent takes claude or codex" ;; esac; shift 2 ;;
        --ref) ref=${2:?--ref needs a branch, tag or commit}; shift 2 ;;
        --dir) dir=${2:?--dir needs a directory}; shift 2 ;;
        --no-selftest) selftest=false; shift ;;
        --dry-run) dry=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
done

case "$dir" in /*) ;; *) die "--dir takes an absolute path" ;; esac
[ -n "$owner" ] || die "name the user the agents run as: --user NAME"
[ "$owner" != root ] || die "the user the agents run as is not root: --user NAME"
home=$(getent passwd "$owner" | cut -d: -f6) || die "no user $owner"
[ -n "$home" ] || die "no home directory for $owner"
if [ ${#agents[@]} -eq 0 ]; then
    agents=(claude)
    if [ -d "$home/.codex" ]; then agents+=(codex); fi
fi
agent_args=()
for a in "${agents[@]}"; do agent_args+=(--agent "$a"); done
jevguard="$dir/bin/jevguard"

if $dry; then
    echo "would install jevguard for the system:"
    echo "  for user:   $owner ($home)"
    echo "  agents:     ${agents[*]}"
    if [ -d "$dir/.git" ]; then
        echo "  code:       update the clone in $dir to $ref"
    else
        echo "  code:       clone $repo into $dir, at $ref"
    fi
    echo "  then:       $jevguard setup-system --user $owner ${agent_args[*]}"
    if [ ! -e /etc/jevguard/typesafe.key ]; then echo "              and ask for the API key, if setup finds none to bring over"; fi
    echo "  check:      jevguard status$($selftest && echo ', jevguard selftest')"
    exit 0
fi

[ "$(id -u)" -eq 0 ] || die "run it as root: sudo bash install.sh"
# This script, and every directory above it, root's and writable by root alone: else whoever
# could write there could have changed what root is running now.
self=${BASH_SOURCE[0]:-}
[ -f "$self" ] || die "run it from a file in a clone only root can write, not from a pipe (see the top of the script)"
p=$(readlink -f "$self")
while :; do
    read -r uid mode < <(stat -c '%u %a' "$p")
    if [ "$uid" -ne 0 ] || [ $((8#$mode & 8#022)) -ne 0 ]; then
        die "$p is not root's alone; clone the code as root and run its install.sh (see the top of the script)"
    fi
    [ "$p" = / ] && break
    p=$(dirname "$p")
done
for tool in git systemctl getent; do
    command -v "$tool" >/dev/null || die "$tool is needed"
done
/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null \
    || die "/usr/bin/python3 has to be 3.11 or newer"

# ---- the code: a clone only root can write ----------------------------------------------------
if [ -d "$dir/.git" ]; then
    echo "updating $dir"
    git -C "$dir" fetch --quiet --tags origin
else
    [ ! -e "$dir" ] || die "$dir is there and is not a clone of jevguard"
    echo "cloning $repo into $dir"
    git clone --quiet "$repo" "$dir"
fi
if git -C "$dir" rev-parse --quiet --verify "refs/remotes/origin/$ref" >/dev/null; then
    git -C "$dir" checkout --quiet -B "$ref" "origin/$ref"
else
    git -C "$dir" checkout --quiet --detach "$ref"
fi
echo "code at $(git -C "$dir" log -1 --format='%h %s')"

# ---- the installation -------------------------------------------------------------------------
setup() { "$jevguard" setup-system --user "$owner" "${agent_args[@]}"; }
status=0
setup || status=$?
if [ ! -e /etc/jevguard/typesafe.key ] && getent group jevguard >/dev/null; then
    # No key was brought over from an installation in the home. The owner types it in; it is
    # not shown, and it is not given to any command line.
    [ -t 0 ] || die "no API key yet: run this again in a terminal, or put it in /etc/jevguard/typesafe.key (README)"
    read -rsp "TypeSafe API key (not shown): " key
    echo
    [ -n "$key" ] || die "no key given; nothing more done"
    tmp=$(mktemp /etc/jevguard/.typesafe.key.XXXXXX)
    printf '%s\n' "$key" > "$tmp"
    unset key
    chgrp jevguard "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" /etc/jevguard/typesafe.key
    echo "API key put in /etc/jevguard/typesafe.key; running setup again"
    status=0
    setup || status=$?
fi
[ "$status" -eq 0 ] || die "setup did not complete (above); the user's own hooks were left where it says so"

# ---- the check -----------------------------------------------------------------------------------
echo
"$jevguard" status --days 1
if $selftest; then
    echo
    "$jevguard" selftest || die "the selftest failed: the scores came back wrong, or none came back"
fi

cat <<JEVGUARD_NEXT_END

Done. Next:
  1. Close every Claude Code and Codex session, and start new ones.
  2. In Claude Code, /status lists "Enterprise managed settings (file)" among the setting sources.
     If it says (remote), the file is not read: an organization's settings win.
  3. Have the agent fetch any page, then: sudo jevguard log --all -n 3
  4. Once that works, remove what setup named above as the old copies in $home.
JEVGUARD_NEXT_END
if [ -e "$home/.local/share/jevguard" ] || [ -L "$home/.local/bin/jevguard" ]; then
    echo "     The old installation's code and command can go then as well:"
    if [ -L "$home/.local/bin/jevguard" ]; then echo "       rm $home/.local/bin/jevguard"; fi
    if [ -e "$home/.local/share/jevguard" ]; then echo "       rm -rf $home/.local/share/jevguard"; fi
fi
echo "To update later: sudo bash $dir/install.sh"
}

main "$@"
exit
