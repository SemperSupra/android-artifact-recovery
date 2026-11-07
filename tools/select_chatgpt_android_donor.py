#!/usr/bin/env python3
"""Conservative incremental admission of expensive ChatGPT Android donor work.

A PR path filter checks the entire PR diff, so changing a lightweight comparator
would otherwise reacquire the same large signed APK and rerun JADX repeatedly.
On synchronize events, compare only the actual previous/new commit range.
Unknown ancestry, missing git, or manual dispatch always admits acquisition.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

SHA = re.compile(r"^[a-fA-F0-9]{40}$")
ACQUISITION_INPUTS = frozenset({
    ".github/workflows/recover-chatgpt-public.yml",
    "tools/summarize_android_surface.py",
    "tools/qualify_jadx_log.py",
    "tools/qualify_android_abi.py",
    "tools/qualify_dex_header_inventory.py",
})


def select(event_name: str, event: dict) -> tuple[bool, str]:
    if event_name != "pull_request" or event.get("action") != "synchronize":
        return True, "INITIAL_OR_MANUAL_EVENT"
    before = event.get("before")
    after = event.get("after")
    if not (isinstance(before, str) and SHA.fullmatch(before)
            and isinstance(after, str) and SHA.fullmatch(after)):
        return True, "UNVERIFIABLE_ANCESTRY_RUN_CONSERVATIVELY"
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", before, after],
            check=True, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return True, "UNVERIFIABLE_DIFF_RUN_CONSERVATIVELY"
    changed = {x.strip() for x in result.stdout.splitlines() if x.strip()}
    if ACQUISITION_INPUTS & changed:
        return True, "ACQUISITION_INPUT_CHANGED"
    return False, "SOURCE_ONLY_CHANGE_SKIP_DONOR"


def main() -> int:
    try:
        event = json.loads(Path(os.environ.get("GITHUB_EVENT_PATH", "")).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        event = {}
    acquire, reason = select(os.environ.get("GITHUB_EVENT_NAME", ""), event)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write("acquire=" + ("true" if acquire else "false") + chr(10))
            out.write("reason=" + reason + chr(10))
    print(json.dumps({
        "schema": "aar-chatgpt-android-donor-admission/v1",
        "acquire": acquire, "reason": reason,
        "original_runtime_qualified": False,
        "claim_boundary": "A skipped donor job is NOT an APK/code/runtime verification result.",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
