#!/usr/bin/env python3
# PreToolUse hook: auto-approve `sed` invocations whose file arguments all
# resolve under $CLAUDE_PROJECT_DIR. Stdin-mode sed (no file args) is also
# auto-approved. Anything else falls through to the normal permission prompt.

import json
import os
import re
import shlex
import sys
from pathlib import Path


def emit_allow(reason: str) -> None:
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )
    sys.exit(0)


def fall_through() -> None:
    sys.exit(0)


try:
    payload = json.load(sys.stdin)
except Exception:
    fall_through()

if payload.get("tool_name") != "Bash":
    fall_through()

cmd = payload.get("tool_input", {}).get("command", "")

# Must be a bare sed invocation: no env prefix, no chaining.
if not re.match(r"^sed(\s|$)", cmd):
    fall_through()

# Reject shell chaining / expansion that could let sed touch something the
# literal command line doesn't name.
if re.search(r"[;&|`]|\$\(|>\(|<\(", cmd):
    fall_through()

try:
    toks = shlex.split(cmd)
except ValueError:
    fall_through()

toks = toks[1:]  # drop "sed"

# Separate sed-script options from positional file args.
files: list[str] = []
saw_script = False
i = 0
while i < len(toks):
    t = toks[i]
    if t == "--":
        files.extend(toks[i + 1 :])
        break
    if t in ("-e", "--expression", "-f", "--file"):
        saw_script = True
        i += 2
        continue
    if t.startswith("--expression=") or t.startswith("--file="):
        saw_script = True
        i += 1
        continue
    if t.startswith("-") and t != "-":
        # Bundled short options (-n, -E, -i[SUFFIX], etc.) — no value follows.
        i += 1
        continue
    if not saw_script:
        # First positional is the inline script when no -e/-f was given.
        saw_script = True
        i += 1
        continue
    files.append(t)
    i += 1

if not files:
    emit_allow("sed stdin-mode (no file args)")

project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()

for f in files:
    if f == "-":
        continue  # explicit stdin
    p = Path(f)
    if not p.is_absolute():
        p = project_dir / p
    try:
        resolved = p.resolve(strict=False)
    except Exception:
        fall_through()
    try:
        resolved.relative_to(project_dir)
    except ValueError:
        fall_through()

emit_allow(f"sed targets all under {project_dir}")
