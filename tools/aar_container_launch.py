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
               prepare_output: bool = True, platform: str | None = None,
               profile: str = "python-core") -> list[str]:
    if not test_image and not PIN.fullmatch(image):
        raise ValueError("image must be immutable digest ref (registry/repo@sha256:...)")
    if platform is not None and platform not in ("linux/amd64", "linux/arm64"):
        raise ValueError("unsupported OCI execution platform")
    if profile not in ("python-core", "java-static", "sdk-mounted"):
        raise ValueError("unsupported capability profile")
    if action not in ("probe", "plan", "run", "verify"):
        raise ValueError("unsupported action")
    if action != "probe" and (source is None or output is None):
        raise ValueError("plan, run and verify require --artifact and --work-root")
    if action != "probe" and profile != "python-core":
        raise ValueError("case admission uses python-core; other profiles are probe-only")
    if action == "probe" and (source is not None or output is not None):
        raise ValueError("probe does not accept corpus paths or output mounts")
    args = [engine, "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "2g", "--cpus", "2",
            "--tmpfs", "/tmp:rw,nosuid,size=256m"]
    if platform:
        args += ["--platform", platform]
    if os.name != "nt":
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
    if action == "probe":
        args += [image, "python", "tools/aar_image_parity.py", "probe",
                 "--profile", profile]
        return args

    candidate = source.expanduser()
    if candidate.is_symlink():
        raise ValueError("input artifact symlink is not allowed")
    src = candidate.resolve(strict=True)
    if not src.is_file():
        raise ValueError("artifact must be an existing regular file")

    output_candidate = output.expanduser()
    if output_candidate.is_symlink():
        raise ValueError("output symlink is not allowed")
    dest = output_candidate.resolve()
    if dest == src.parent or dest in src.parents or dest == src:
        raise ValueError("output must not contain input artifact")
    # Docker --mount uses comma-delimited key/value options even with argv lists.
    if any("," in str(p) or "\n" in str(p) for p in (src, dest)):
        raise ValueError("Docker mount path contains unsupported delimiter")

    # Mount the *exact file*, never its directory: a specimen may share a folder
    # with other proprietary APKs, keys or credentials.
    args += ["--mount", f"type=bind,src={src},dst=/inputs/artifact.apk,readonly"]
    if action == "run":
        if prepare_output:
            dest.mkdir(parents=True, exist_ok=True)
            if not dest.is_dir():
                raise ValueError("output is not a directory")
        args += ["--mount", f"type=bind,src={dest},dst=/work"]
    elif action == "verify":
        if not dest.is_dir():
            raise ValueError("verification requires an existing output directory")
        args += ["--mount", f"type=bind,src={dest},dst=/work,readonly"]
    # plan is read-only and needs no evidence bind; it reports the deterministic
    # future location but never creates it.
    args += [image, "python", "tools/aar_local_case.py", action,
             "/inputs/artifact.apk", "--work-root", "/work"]
    return args

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "plan", "run", "verify"))
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"),
                        help="Explicitly select the OCI substrate/ABI for parity")
    parser.add_argument("--image", required=True)
    parser.add_argument("--profile", choices=("python-core", "java-static", "sdk-mounted"),
                        default="python-core", help="probe capability; case admission uses python-core")
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
                          prepare_output=not args.dry_run, platform=args.platform,
                          profile=args.profile)
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
