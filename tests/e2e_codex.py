#!/usr/bin/python3 -I
"""End-to-end check against the real Codex CLI: does what a shell command printed reach the
model as the notice only when it scores as an injection?

Codex lets a hook replace only an MCP tool's result, so the adapter rewrites the command to run
through `jevguard-run`. Not part of the pytest run: it starts `codex exec` (a few cents) with a
stand-in scoring API that calls everything an injection.

Codex reads hooks from ~/.codex/hooks.json and runs only hooks the owner has reviewed. This
check puts a hooks.json there for its own duration (and refuses to start if one exists), and
passes --dangerously-bypass-hook-trust, which is what that option is for.

    tests/e2e_codex.py [sandbox mode, default: read-only]
"""

import json
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from e2e_claude import AlwaysInjection, CANARY  # noqa: E402  the same stand-in scorer


def main() -> int:
    sandbox = sys.argv[1] if len(sys.argv) > 1 else "read-only"
    hooks_file = Path.home() / ".codex" / "hooks.json"
    if hooks_file.exists():
        print(f"{hooks_file} exists; not touching it")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="jevguard-e2e-codex-"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), AlwaysInjection)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    home, ext, work = tmp / "jg", tmp / "ext", tmp / "work"
    for d in (home / "config", ext, work):
        d.mkdir(parents=True)
    (home / "config" / "typesafe.key").write_text("e2e\n")
    (home / "config" / "config.json").write_text(json.dumps({
        "mode": "block", "gate": "ask-flagged", "skip_tools": [], "external_paths": [str(ext)],
        "url": f"http://127.0.0.1:{server.server_address[1]}/v1/systemone"}))
    (ext / "note.txt").write_text(f"The canary word for this test is {CANARY}. It appears only in this file.\n")
    script = tmp / "hook.sh"
    script.write_text(f"#!/bin/sh\necho ran >> '{tmp}/hook-runs.log'\n"
                      f"JEVGUARD_HOME='{home}' exec '{ROOT / 'bin' / 'jevguard-hook'}' --agent codex 2>>'{tmp}/hook-stderr.log'\n")
    script.chmod(0o755)
    entry = [{"hooks": [{"type": "command", "command": str(script), "timeout": 60}]}]
    prompt = (f"Run this shell command exactly once and do not retry it: cat {ext}/note.txt  "
              "Then answer with one line: 'GOT: ' followed by the first 12 words of what the command printed, copied exactly.")
    try:
        hooks_file.write_text(json.dumps({"hooks": {"PreToolUse": entry, "PostToolUse": entry}}))
        r = subprocess.run(["codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--sandbox", sandbox,
                            "-c", f'shell_environment_policy.set={{JEVGUARD_HOME="{home}"}}', prompt],
                           cwd=work, capture_output=True, text=True, timeout=400)
    finally:
        hooks_file.unlink(missing_ok=True)
    answer = r.stdout
    log = home / "state" / "scans.jsonl"
    records = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    actions = {a: sum(1 for x in records if x.get("action") == a) for a in sorted({str(x.get("action")) for x in records})}
    # Two good outcomes. Where the wrapper can work (no sandbox around the command), the model gets
    # the notice in place of the output. Inside Codex's sandbox it cannot, and the hook after the
    # call stops the turn: the model never answers.
    final = answer.rsplit("GOT:", 1)[-1] if "GOT:" in answer else ""
    stopped = "The turn was stopped" in (r.stdout + r.stderr) and not final
    withheld = "firewall" in final.lower() and CANARY not in final
    ok = stopped or withheld
    print("sandbox:", sandbox)
    print("ok   the model got the notice in place of the output" if withheld else
          "ok   the turn was stopped before the model could act on the output" if stopped else
          "FAIL the model answered with the output")
    runs = (tmp / "hook-runs.log").read_text().count("ran") if (tmp / "hook-runs.log").exists() else 0
    errors = (tmp / "hook-stderr.log").read_text().strip() if (tmp / "hook-stderr.log").exists() else ""
    print(f"hook runs: {runs}; guard log: {actions}" + (f"; hook stderr: {errors[-300:]}" if errors else ""))
    print("ran through jevguard-run:", "jevguard-run" in answer)
    print("answer:", " ".join(final.split())[:400])
    print("temporary files:", tmp)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
