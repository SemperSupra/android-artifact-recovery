#!/usr/bin/env python3
"""Fail-closed Docker/Podman host adapter for immutable AAR OCI tool capsules.

A Docker engine is not needed for --dry-run. Real runs never expose an actor
credential, model endpoint, Docker socket, or live network to the tool image.
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

PIN = re.compile(r"^(?:[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[a-z0-9._-]+)?@)?sha256:[0-9a-f]{64}$")


def build_argv(*, engine: str, image: str, action: str, source: pathlib.Path | None,
               output: pathlib.Path | None, test_image: bool = False,
               prepare_output: bool = True) -> list[str]:
    if not test_image and not PIN.fullmatch(image):
        raise ValueError("image must be immutable digest ref (registry/repo@sha256:...)")
    if action != "probe" and (source is None or output is None):
        raise ValueError("run, plan and verify require --artifact and --work-root")
    if action == "probe" and (source is not None or output is not None):
        raise ValueError("probe does not accept a corpus path or output mount")
    args = [engine, "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "2g", "--cpus", "2",
            "--tmpfs", "/tmp:rw,nosuid,size=256m"]
    if os.name != "nt":
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    if action == "probe":
        args += [image, "python", "tools/aar_image_parity.py", "probe",
                 "--profile", "python-core"]
    else:
        src = source.expanduser().resolve(strict=True)
        if not src.is_file() or src.is_symlink():
            raise ValueError("artifact must be an existing non-symlink file")
        dest = output.expanduser().resolve()
        if src.parent == dest or dest in src.parents:
            raise ValueError("output directory must not contain the input artifact")
        # Caller chooses the destination; create it explicitly once with host permissions.
        if prepare_output:
            dest.mkdir(parents=True, exist_ok=True)
            if not dest.is_dir():
                raise ValueError("output is not a directory")
        args += ["--mount", f"type=bind,src={src.parent},dst=/inputs,readonly",
                 "--mount", f"type=bind,src={dest},dst=/work",
                 image, "python", "tools/aar_local_case.py", action,
                 f"/inputs/{src.name}", "--work-root", "/work"]
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "plan", "run", "verify"))
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--image", required=True)
    parser.add_argument("--artifact", type=pathlib.Path)
    parser.add_argument("--work-root", type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-local-test-tag", action="store_true",
                        help="CI-only, never production promotion")
    args = parser.parse_args()
    try:
        argv = build_argv(engine=args.engine, image=args.image, action=args.action,
                          source=args.artifact, output=args.work_root,
                          test_image=args.allow_local_test_tag,
                          prepare_output=not args.dry_run)
        if args.dry_run:
            print(json.dumps({"schema":"aar-oci-launch-preview/v0", "argv":argv,
                              "executed":False, "network":"none", "claims":"NONE"}, indent=2))
            return 0
        if shutil.which(args.engine) is None:
            raise ValueError(f"container runtime not installed: {args.engine}")
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, check=False)
        return proc.returncode
    except (OSError, ValueError, FileNotFoundError) as error:
        print(json.dumps({"status":"BLOCKED","reason":str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
