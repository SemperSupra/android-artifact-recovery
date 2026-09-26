#!/usr/bin/env python3
"""Host-neutral Google Play AVD bootstrap: observe -> plan -> apply -> verify -> cleanup.

All mutable state is project-local. The CLI emits the same receipt model for
humans, automation, and actors; --format human is concise, --format json is
stable machine-readable output.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "docs" / "acquisition" / "play-host-lock.json"
SCHEMA = "aar-play-host/v1"
PLAN_SCHEMA = "aar-play-host-plan/v1"
DEFAULT_STATE = ROOT / ".local" / "play-host"
EXIT_UNSUPPORTED = 2
EXIT_VENUE = 3
EXIT_FAILURE = 4


class AarHostError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        failure_type: str = "failure",
        exit_code: int = EXIT_FAILURE,
        evidence: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.failure_type = failure_type
        self.exit_code = exit_code
        self.evidence = evidence or {}


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise AarHostError(f"{path}: expected JSON object", failure_type="invalid_state")
    return value


def atomic_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    actual = argv
    if os.name == "nt" and pathlib.Path(argv[0]).suffix.casefold() in {".bat", ".cmd"}:
        actual = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", subprocess.list2cmdline(argv)]
    try:
        cp = subprocess.run(
            actual,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        raise AarHostError(f"command timeout: {pathlib.Path(argv[0]).name}", failure_type="timeout") from exc
    if check and cp.returncode:
        detail = (cp.stderr or cp.stdout).strip()[-1200:]
        raise AarHostError(f"command failed ({cp.returncode}): {pathlib.Path(argv[0]).name}: {detail}")
    return cp


def normalize_host(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    s = (system or platform.system()).casefold()
    m = (machine or platform.machine()).casefold()
    os_name = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(s, s)
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)
    return os_name, arch


def load_lock() -> dict[str, Any]:
    lock = read_json(LOCK_PATH)
    if lock.get("schema") != "aar-play-host-lock/v1":
        raise AarHostError("unsupported play-host lock schema", failure_type="lock_invalid")
    return lock


def host_profile(
    lock: dict[str, Any], system: str | None = None, machine: str | None = None
) -> tuple[str, dict[str, Any]]:
    os_name, arch = normalize_host(system, machine)
    key = f"{os_name}-{arch}"
    if key in lock.get("unsupported", {}):
        raise AarHostError(
            lock["unsupported"][key], failure_type="unsupported_host", exit_code=EXIT_UNSUPPORTED
        )
    profile = lock.get("profiles", {}).get(key)
    if not profile:
        raise AarHostError(
            f"unsupported host: {os_name}/{arch}", failure_type="unsupported_host", exit_code=EXIT_UNSUPPORTED
        )
    return key, profile


def executable(name: str, os_name: str) -> str:
    return name + ".exe" if os_name == "windows" else name


def sdk_script(name: str, os_name: str) -> str:
    return name + ".bat" if os_name == "windows" else name


def memory_bytes(os_name: str) -> int | None:
    try:
        if os_name == "windows":
            cp = run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
                ],
                check=False,
                timeout=20,
            )
            return int(cp.stdout.strip()) if cp.returncode == 0 and cp.stdout.strip().isdigit() else None
        return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, AarHostError):
        return None


def host_acceleration_observation(os_name: str, profile: dict[str, Any]) -> dict[str, Any]:
    backend = profile["acceleration"]
    if os_name == "linux":
        kvm = pathlib.Path("/dev/kvm")
        return {
            "backend": backend,
            "device": "/dev/kvm",
            "present": kvm.exists(),
            "readable": os.access(kvm, os.R_OK),
            "writable": os.access(kvm, os.W_OK),
        }
    if os_name == "macos":
        cp = run(["/usr/sbin/sysctl", "-n", "kern.hv_support"], check=False, timeout=20)
        return {
            "backend": backend,
            "sysctl": "kern.hv_support",
            "value": cp.stdout.strip() if cp.returncode == 0 else None,
            "probe_exit": cp.returncode,
        }
    cp = run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$c=Get-CimInstance Win32_ComputerSystem; "
            "[pscustomobject]@{HypervisorPresent=$c.HypervisorPresent} | ConvertTo-Json -Compress",
        ],
        check=False,
        timeout=20,
    )
    return {
        "backend": backend,
        "probe_exit": cp.returncode,
        "evidence": cp.stdout.strip()[:500] if cp.stdout.strip() else None,
    }


def base_receipt(
    command: str,
    profile_key: str | None,
    profile: dict[str, Any] | None,
    state_root: pathlib.Path,
) -> dict[str, Any]:
    os_name, arch = normalize_host()
    return {
        "schema": SCHEMA,
        "command": command,
        "observed_at": utcnow(),
        "status": "unknown",
        "result_class": "UNKNOWN",
        "failure_type": None,
        "host": {
            "os": os_name,
            "architecture": arch,
            "profile": profile_key,
            "platform": platform.platform(),
            "runner_name": os.environ.get("RUNNER_NAME"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "memory_bytes": memory_bytes(os_name),
            "disk": None,
        },
        "profile": profile,
        "state_root": str(state_root),
        "next_action": None,
        "evidence": {},
    }


def write_receipt(state_root: pathlib.Path, receipt: dict[str, Any]) -> pathlib.Path:
    state_root.mkdir(parents=True, exist_ok=True)
    receipt_dir = state_root / "receipts"
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = receipt_dir / f"{stamp}-{receipt['command']}.json"
    receipt["receipt"] = str(path)
    atomic_json(path, receipt)
    return path


def observe(state_root: pathlib.Path) -> dict[str, Any]:
    lock = load_lock()
    try:
        key, profile = host_profile(lock)
    except AarHostError as exc:
        receipt = base_receipt("observe", None, None, state_root)
        receipt.update(
            status="unsupported_host",
            result_class="UNSUPPORTED",
            failure_type=exc.failure_type,
            next_action="select a supported host/architecture",
        )
        receipt["evidence"]["reason"] = str(exc)
        write_receipt(state_root, receipt)
        return receipt
    receipt = base_receipt("observe", key, profile, state_root)
    usage = shutil.disk_usage(state_root.parent if state_root.parent.exists() else ROOT)
    receipt["host"]["disk"] = {"total": usage.total, "used": usage.used, "free": usage.free}
    receipt["evidence"]["acceleration"] = host_acceleration_observation(profile["os"], profile)
    runtime_root = state_root / "runtime" / key
    receipt["evidence"]["existing_runtime"] = runtime_root.exists()
    receipt.update(
        status="observed",
        result_class="PASS",
        next_action="plan --accept-sdk-licenses" if not runtime_root.exists() else "inspect existing runtime or cleanup",
    )
    write_receipt(state_root, receipt)
    return receipt


def plan_file(state_root: pathlib.Path, plan_id: str) -> pathlib.Path:
    return state_root / "plans" / f"{plan_id}.json"


def create_plan(state_root: pathlib.Path, accept_sdk_licenses: bool) -> dict[str, Any]:
    if not accept_sdk_licenses:
        raise AarHostError(
            "SDK license acceptance is an explicit apply boundary; rerun plan with --accept-sdk-licenses",
            failure_type="license_acceptance_required",
        )
    lock = load_lock()
    key, profile = host_profile(lock)
    runtime = state_root / "runtime" / key
    if runtime.exists():
        raise AarHostError(
            f"runtime already exists: {runtime}; inspect or cleanup before a new plan",
            failure_type="existing_state",
        )
    plan_id = "play-host-" + key + "-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    value = {
        "schema": PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": utcnow(),
        "status": "planned",
        "profile_key": key,
        "profile": profile,
        "runtime_root": str(runtime),
        "lock_path": str(LOCK_PATH.relative_to(ROOT)),
        "lock_sha256": sha256_file(LOCK_PATH),
        "implementation_sha256": sha256_file(pathlib.Path(__file__)),
        "accept_sdk_licenses": True,
        "mutations": [
            "create project-local runtime root",
            "download checksum-pinned Temurin JDK, Android command-line tools, and Emulator",
            "accept Android SDK licenses inside the project-local SDK",
            "install exact expected platform-tools/build-tools/system-image package revisions",
            "create one project-local unauthenticated Google Play AVD",
        ],
        "prohibited": [
            "global PATH/environment persistence",
            "system package installation",
            "host service/registry mutation",
            "credential or Play-account materialization",
        ],
    }
    path = plan_file(state_root, plan_id)
    atomic_json(path, value)
    receipt = base_receipt("plan", key, profile, state_root)
    receipt.update(status="planned", result_class="PASS", next_action=f"apply --plan {path}")
    receipt["evidence"] = {
        "plan": str(path),
        "plan_sha256": sha256_file(path),
        "mutations": value["mutations"],
    }
    write_receipt(state_root, receipt)
    return receipt


def safe_extract_zip(archive: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            rel = pathlib.PurePosixPath(member.filename)
            if rel.is_absolute() or ".." in rel.parts:
                raise AarHostError(f"unsafe zip entry: {member.filename}", failure_type="archive_invalid")
        zf.extractall(destination)


def safe_extract_tar(archive: pathlib.Path, destination: pathlib.Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            rel = pathlib.PurePosixPath(member.name)
            if rel.is_absolute() or ".." in rel.parts:
                raise AarHostError(f"unsafe tar entry: {member.name}", failure_type="archive_invalid")
        # Python's data filter permits safe in-tree links while rejecting
        # absolute/out-of-tree link targets and special-device extraction.
        tf.extractall(destination, filter="data")


def download(url: str, expected_sha256: str, destination: pathlib.Path) -> pathlib.Path:
    if destination.is_file() and sha256_file(destination) == expected_sha256:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    part.unlink(missing_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "SemperSupra-AAR-play-host/1"})
    with urllib.request.urlopen(request, timeout=90) as response, part.open("wb") as stream:
        while block := response.read(8 * 1024 * 1024):
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    observed = sha256_file(part)
    if observed != expected_sha256:
        part.unlink(missing_ok=True)
        raise AarHostError(f"download checksum mismatch: {url}", failure_type="checksum_mismatch")
    part.replace(destination)
    return destination


def install_archive(archive: pathlib.Path, destination: pathlib.Path) -> None:
    staging = destination.parent / (destination.name + ".extracting")
    if staging.exists():
        shutil.rmtree(staging)
    if archive.name.endswith(".zip"):
        safe_extract_zip(archive, staging)
    else:
        safe_extract_tar(archive, staging)
    children = [p for p in staging.iterdir() if p.name != "__MACOSX"]
    source = children[0] if len(children) == 1 and children[0].is_dir() else staging
    if destination.exists():
        raise AarHostError(f"destination already exists: {destination}", failure_type="existing_state")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source == staging:
        staging.rename(destination)
    else:
        source.rename(destination)
        shutil.rmtree(staging, ignore_errors=True)


def ensure_unix_executable_tree(root: pathlib.Path, os_name: str) -> None:
    if os_name == "windows":
        return
    for item in root.rglob("*"):
        if item.is_file():
            item.chmod(item.stat().st_mode | 0o100)


def source_properties(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def process_env(runtime: pathlib.Path, profile: dict[str, Any]) -> dict[str, str]:
    sdk = runtime / "sdk"
    java_root = runtime / "jdk"
    os_name = profile["os"]
    java_exe = next(java_root.rglob(executable("java", os_name)), None)
    if not java_exe:
        raise AarHostError("project-local Java executable not found", failure_type="toolchain_invalid")
    java_home = java_exe.parent.parent
    env = os.environ.copy()
    env.update(
        {
            "ANDROID_HOME": str(sdk),
            "ANDROID_SDK_ROOT": str(sdk),
            "ANDROID_AVD_HOME": str(runtime / "avd"),
            "ANDROID_USER_HOME": str(runtime / "user-home" / ".android"),
            "ANDROID_EMULATOR_HOME": str(runtime / "user-home" / ".android"),
            "ANDROID_SDK_HOME": str(runtime / "user-home"),
            "JAVA_HOME": str(java_home),
        }
    )
    env["PATH"] = os.pathsep.join(
        [str(java_exe.parent), str(sdk / "platform-tools"), str(sdk / "emulator"), env.get("PATH", "")]
    )
    for path in (runtime / "avd", runtime / "user-home" / ".android"):
        path.mkdir(parents=True, exist_ok=True)
    return env


def sdkmanager_path(runtime: pathlib.Path, profile: dict[str, Any]) -> pathlib.Path:
    return (
        runtime
        / "sdk"
        / "cmdline-tools"
        / "19.0"
        / "bin"
        / sdk_script("sdkmanager", profile["os"])
    )


def avdmanager_path(runtime: pathlib.Path, profile: dict[str, Any]) -> pathlib.Path:
    return (
        runtime
        / "sdk"
        / "cmdline-tools"
        / "19.0"
        / "bin"
        / sdk_script("avdmanager", profile["os"])
    )


def verify_revision(path: pathlib.Path, expected: str, label: str) -> dict[str, Any]:
    props = source_properties(path / "source.properties")
    observed = props.get("Pkg.Revision")
    if observed != expected:
        raise AarHostError(
            f"{label} revision mismatch: observed={observed!r} expected={expected!r}",
            failure_type="toolchain_drift",
        )
    return {
        "revision": observed,
        "source_properties_sha256": sha256_file(path / "source.properties"),
    }


def critical_identity(
    runtime: pathlib.Path, lock: dict[str, Any], key: str, profile: dict[str, Any]
) -> dict[str, Any]:
    sdk = runtime / "sdk"
    os_name = profile["os"]
    image = sdk / "system-images" / "android-35" / "google_apis_playstore" / profile["image_abi"]
    java = next((runtime / "jdk").rglob(executable("java", os_name)), None)
    adb = sdk / "platform-tools" / executable("adb", os_name)
    emulator = sdk / "emulator" / executable("emulator", os_name)
    apksigner = sdk / "build-tools" / "35.0.0" / "lib" / "apksigner.jar"
    cmd_props = sdk / "cmdline-tools" / "19.0" / "source.properties"
    image_props = image / "source.properties"
    for path in (java, adb, emulator, apksigner, cmd_props, image_props):
        if path is None or not pathlib.Path(path).is_file():
            raise AarHostError(f"critical toolchain file missing: {path}", failure_type="toolchain_invalid")

    java_cp = run([str(java), "-version"], check=False)
    java_version = (java_cp.stderr + java_cp.stdout).strip()
    expected_java = lock["java"]["version"]
    if expected_java not in java_version:
        raise AarHostError(f"JDK mismatch: expected {expected_java}", failure_type="toolchain_drift")

    cmd = verify_revision(
        sdk / "cmdline-tools" / "19.0", lock["android"]["cmdline_tools"]["version"], "cmdline-tools"
    )
    platform_tools = verify_revision(
        sdk / "platform-tools", lock["android"]["packages"]["platform-tools"], "platform-tools"
    )
    build_tools = verify_revision(
        sdk / "build-tools" / "35.0.0",
        lock["android"]["packages"]["build-tools;35.0.0"],
        "build-tools",
    )
    emulator_meta = verify_revision(
        sdk / "emulator", lock["android"]["emulator"]["version"], "emulator"
    )
    image_meta = verify_revision(
        image, lock["android"]["packages"]["system_image_revision"], "system-image"
    )
    image_props_map = source_properties(image_props)
    if (
        image_props_map.get("AndroidVersion.ApiLevel") != "35"
        or image_props_map.get("SystemImage.TagId") != "google_apis_playstore"
        or image_props_map.get("SystemImage.Abi") != profile["image_abi"]
    ):
        raise AarHostError("system image identity mismatch", failure_type="toolchain_drift")

    files = {
        "java": sha256_file(java),
        "adb": sha256_file(adb),
        "emulator": sha256_file(emulator),
        "apksigner.jar": sha256_file(apksigner),
        "cmdline-tools/source.properties": sha256_file(cmd_props),
        "system-image/source.properties": sha256_file(image_props),
    }
    identity = {
        "profile": key,
        "java_version": expected_java,
        "cmdline_tools": cmd,
        "platform_tools": platform_tools,
        "build_tools": build_tools,
        "emulator": emulator_meta,
        "system_image": image_meta,
        "critical_files_sha256": files,
    }
    identity["identity_sha256"] = json_sha256(identity)
    return identity


def validate_plan(
    plan_path: pathlib.Path, state_root: pathlib.Path
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any], pathlib.Path]:
    plan = read_json(plan_path)
    if plan.get("schema") != PLAN_SCHEMA:
        raise AarHostError("invalid plan schema", failure_type="invalid_plan")
    if plan.get("lock_sha256") != sha256_file(LOCK_PATH):
        raise AarHostError(
            "lock changed after plan creation; create a fresh plan", failure_type="stale_plan"
        )
    if plan.get("implementation_sha256") != sha256_file(pathlib.Path(__file__)):
        raise AarHostError(
            "implementation changed after plan creation; create a fresh plan",
            failure_type="stale_plan",
        )
    lock = load_lock()
    key, profile = host_profile(lock)
    if key != plan.get("profile_key"):
        raise AarHostError("plan host/profile does not match this runtime", failure_type="stale_plan")
    runtime = pathlib.Path(plan["runtime_root"]).resolve()
    expected = (state_root / "runtime" / key).resolve()
    if runtime != expected:
        raise AarHostError(
            "plan runtime root escaped fixed project-local profile root", failure_type="invalid_plan"
        )
    return plan, lock, key, profile, runtime


def apply(plan_path: pathlib.Path, state_root: pathlib.Path) -> dict[str, Any]:
    plan, lock, key, profile, runtime = validate_plan(plan_path, state_root)
    if plan.get("status") in {"applied", "verified"}:
        identity = critical_identity(runtime, lock, key, profile)
        if identity != plan.get("toolchain_identity"):
            raise AarHostError("second apply detected toolchain drift", failure_type="toolchain_drift")
        plan["second_apply"] = {
            "status": "no-op",
            "verified_at": utcnow(),
            "identity_sha256": identity["identity_sha256"],
        }
        atomic_json(plan_path, plan)
        receipt = base_receipt("apply", key, profile, state_root)
        receipt.update(status="no-op", result_class="PASS", next_action="cleanup or use verified runtime")
        receipt["evidence"] = {"plan": str(plan_path), "toolchain_identity": identity}
        write_receipt(state_root, receipt)
        return receipt
    if plan.get("status") != "planned":
        raise AarHostError(
            f"apply requires planned state, got {plan.get('status')}", failure_type="invalid_state"
        )
    if runtime.exists():
        raise AarHostError(
            "runtime root appeared after planning; refusing overwrite", failure_type="stale_plan"
        )

    runtime.mkdir(parents=True)
    cache = runtime / "downloads"
    sdk = runtime / "sdk"
    jdk = runtime / "jdk"

    java_spec = lock["java"]["archives"][key]
    cmd_spec = lock["android"]["cmdline_tools"]["archives"][key]
    emu_spec = lock["android"]["emulator"]["archives"][key]

    java_archive = download(
        java_spec["url"], java_spec["sha256"], cache / pathlib.Path(java_spec["url"]).name
    )
    cmd_archive = download(
        cmd_spec["url"], cmd_spec["sha256"], cache / pathlib.Path(cmd_spec["url"]).name
    )
    emu_archive = download(
        emu_spec["url"], emu_spec["sha256"], cache / pathlib.Path(emu_spec["url"]).name
    )

    install_archive(java_archive, jdk)

    cmd_stage = runtime / "cmdline-tools-unpack"
    safe_extract_zip(cmd_archive, cmd_stage)
    cmd_source = cmd_stage / "cmdline-tools"
    if not cmd_source.is_dir():
        raise AarHostError(
            "command-line tools archive layout unexpected", failure_type="archive_invalid"
        )
    cmd_dest = sdk / "cmdline-tools" / "19.0"
    cmd_dest.parent.mkdir(parents=True, exist_ok=True)
    cmd_source.rename(cmd_dest)
    shutil.rmtree(cmd_stage, ignore_errors=True)
    ensure_unix_executable_tree(cmd_dest / "bin", profile["os"])

    emu_stage = runtime / "emulator-unpack"
    safe_extract_zip(emu_archive, emu_stage)
    emu_source = emu_stage / "emulator"
    if not emu_source.is_dir():
        raise AarHostError("emulator archive layout unexpected", failure_type="archive_invalid")
    emu_dest = sdk / "emulator"
    emu_dest.parent.mkdir(parents=True, exist_ok=True)
    emu_source.rename(emu_dest)
    shutil.rmtree(emu_stage, ignore_errors=True)
    ensure_unix_executable_tree(emu_dest, profile["os"])

    env = process_env(runtime, profile)
    sdkmanager = sdkmanager_path(runtime, profile)
    verify_revision(
        cmd_dest, lock["android"]["cmdline_tools"]["version"], "cmdline-tools"
    )
    run(
        [str(sdkmanager), "--sdk_root=" + str(sdk), "--licenses"],
        env=env,
        timeout=240,
        input_text="y\n" * 300,
    )
    packages = ["platform-tools", "build-tools;35.0.0", profile["system_image"]]
    run(
        [str(sdkmanager), "--sdk_root=" + str(sdk), "--install", *packages],
        env=env,
        timeout=1200,
        input_text="y\n" * 300,
    )

    identity = critical_identity(runtime, lock, key, profile)

    avdmanager = avdmanager_path(runtime, profile)
    avd_name = "aar-play-api35-" + profile["image_abi"].replace("-", "_")
    run(
        [
            str(avdmanager),
            "create",
            "avd",
            "--force",
            "--name",
            avd_name,
            "--package",
            profile["system_image"],
            "--device",
            lock["android"]["device"],
        ],
        env=env,
        timeout=180,
        input_text="no\n",
    )
    config_path = runtime / "avd" / f"{avd_name}.avd" / "config.ini"
    if not config_path.is_file():
        raise AarHostError("AVD config missing after creation", failure_type="avd_create_failed")
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write("\nhw.keyboard=yes\nhw.gpu.enabled=yes\nhw.gpu.mode=auto\n")

    plan["status"] = "applied"
    plan["applied_at"] = utcnow()
    plan["avd_name"] = avd_name
    plan["toolchain_identity"] = identity
    atomic_json(plan_path, plan)

    receipt = base_receipt("apply", key, profile, state_root)
    receipt.update(
        status="applied", result_class="PASS", next_action=f"verify --plan {plan_path}"
    )
    receipt["evidence"] = {
        "plan": str(plan_path),
        "toolchain_identity": identity,
        "avd_name": avd_name,
    }
    write_receipt(state_root, receipt)
    return receipt


def emulator_accel_ok(output: str, returncode: int) -> bool:
    if returncode != 0:
        return False
    lower = output.casefold()
    negative = (
        "not installed",
        "not usable",
        "acceleration is not supported",
        "acceleration disabled",
    )
    return not any(marker in lower for marker in negative)


def emulator_venue_failure(log_text: str | None) -> str | None:
    lower = (log_text or "").casefold()
    markers = {
        "hv_unsupported": "hypervisor_framework_unavailable",
        "failed to initialize hvf": "hypervisor_framework_unavailable",
        "whpx is not installed": "acceleration_missing",
        "kvm is not installed": "acceleration_missing",
        "/dev/kvm": "kvm_unavailable",
    }
    for marker, failure in markers.items():
        if marker in lower:
            return failure
    return None


def text_tail(path: pathlib.Path, limit: int = 6000) -> str | None:
    try:
        if not path.is_file():
            return None
        value = path.read_text(encoding="utf-8", errors="replace")
        return value[-limit:]
    except OSError:
        return None


def stop_emulator_process(
    proc: subprocess.Popen[Any] | None,
    *,
    serial: str | None,
    adb: pathlib.Path,
    env: dict[str, str],
    os_name: str,
) -> None:
    if serial:
        run([str(adb), "-s", serial, "emu", "kill"], env=env, timeout=20, check=False)
    if proc is None:
        return
    try:
        proc.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    if os_name == "windows":
        run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"], timeout=30, check=False)
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            proc.terminate()
    try:
        proc.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    if os_name != "windows":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    else:
        proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def emulator_command_prefix(env: dict[str, str], emulator_sudo: bool) -> list[str]:
    if not emulator_sudo:
        return []
    keys = (
        "HOME",
        "PATH",
        "JAVA_HOME",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_AVD_HOME",
        "ANDROID_USER_HOME",
        "ANDROID_EMULATOR_HOME",
        "ANDROID_SDK_HOME",
    )
    assignments = [f"{key}={env[key]}" for key in keys if env.get(key)]
    return ["sudo", "-n", "env", *assignments]


def restore_runtime_ownership(runtime: pathlib.Path) -> dict[str, Any]:
    """Return Linux venue-adapter files to the invoking user after an elevated emulator."""
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        return {"passed": False, "reason": "posix_identity_unavailable"}
    uid = os.getuid()
    gid = os.getgid()
    cp = run(
        ["sudo", "-n", "chown", "-R", f"{uid}:{gid}", str(runtime)],
        timeout=60,
        check=False,
    )
    return {
        "passed": cp.returncode == 0,
        "exit_code": cp.returncode,
        "stderr_tail": cp.stderr.strip()[-500:] or None,
    }


def verify(
    plan_path: pathlib.Path,
    state_root: pathlib.Path,
    boot_timeout: int = 300,
    *,
    emulator_sudo: bool = False,
) -> tuple[dict[str, Any], int]:
    plan, lock, key, profile, runtime = validate_plan(plan_path, state_root)
    if plan.get("status") not in {"applied", "verified"}:
        raise AarHostError("verify requires applied state", failure_type="invalid_state")

    identity = critical_identity(runtime, lock, key, profile)
    if identity != plan.get("toolchain_identity"):
        raise AarHostError(
            "toolchain identity changed before verification", failure_type="toolchain_drift"
        )

    env = process_env(runtime, profile)
    sdk = runtime / "sdk"
    emulator = sdk / "emulator" / executable("emulator", profile["os"])
    adb = sdk / "platform-tools" / executable("adb", profile["os"])

    accel_prefix = emulator_command_prefix(env, emulator_sudo)
    accel = run([*accel_prefix, str(emulator), "-accel-check"], env=env, timeout=60, check=False)
    accel_text = (accel.stdout + "\n" + accel.stderr).strip()
    if not emulator_accel_ok(accel_text, accel.returncode):
        plan["status"] = "venue_limitation"
        plan["verification"] = {
            "status": "venue_limitation",
            "failure_type": "acceleration_missing",
            "acceleration": accel_text[-2000:],
            "verified_at": utcnow(),
        }
        atomic_json(plan_path, plan)
        receipt = base_receipt("verify", key, profile, state_root)
        receipt.update(
            status="venue_limitation",
            result_class="VENUE_LIMITATION",
            failure_type="acceleration_missing",
            next_action="qualify this supported host profile on a venue exposing native virtualization",
        )
        receipt["evidence"] = {
            "plan": str(plan_path),
            "acceleration": accel_text[-2000:],
            "toolchain_identity": identity,
        }
        write_receipt(state_root, receipt)
        return receipt, EXIT_VENUE

    if emulator_sudo and profile["os"] != "linux":
        raise AarHostError(
            "--emulator-sudo is only valid for the Linux KVM permission adapter",
            failure_type="invalid_venue_adapter",
        )
    if emulator_sudo:
        sudo_probe = run(["sudo", "-n", "true"], check=False, timeout=20)
        if sudo_probe.returncode != 0:
            raise AarHostError(
                "passwordless sudo is unavailable for the Linux KVM venue adapter",
                failure_type="venue_adapter_unavailable",
                exit_code=EXIT_VENUE,
            )

    # Keep the ADB server under the ordinary caller identity.  The Linux hosted
    # runner adapter may elevate only the emulator process for /dev/kvm access;
    # starting ADB first prevents root/user ADB-key races.
    adb_start = run([str(adb), "start-server"], env=env, timeout=30, check=False)
    if adb_start.returncode != 0:
        raise AarHostError("failed to start caller-owned ADB server", failure_type="adb_start_failed")

    avd_name = plan["avd_name"]
    log_path = runtime / "emulator.log"
    command = [
        str(emulator),
        "-avd",
        avd_name,
        "-no-window",
        "-no-audio",
        "-no-boot-anim",
        "-no-snapshot-load",
        "-no-snapshot-save",
        "-accel",
        "on",
        "-gpu",
        "swiftshader_indirect",
        "-no-metrics",
    ]
    proc = None
    log = None
    serial = None
    boot_completed = False
    ownership_restore: dict[str, Any] | None = None
    try:
        log = log_path.open("w", encoding="utf-8")
        popen_kwargs: dict[str, Any] = {}
        if profile["os"] == "windows":
            popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_kwargs["start_new_session"] = True
        launch_command = [*emulator_command_prefix(env, emulator_sudo), *command]
        proc = subprocess.Popen(
            launch_command,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            **popen_kwargs,
        )
        deadline = time.monotonic() + boot_timeout
        while time.monotonic() < deadline:
            devices = run([str(adb), "devices"], env=env, timeout=15, check=False).stdout
            for line in devices.splitlines():
                if line.startswith("emulator-") and "\tdevice" in line:
                    serial = line.split("\t", 1)[0]
                    break
            if serial:
                boot = run(
                    [str(adb), "-s", serial, "shell", "getprop", "sys.boot_completed"],
                    env=env,
                    timeout=15,
                    check=False,
                )
                if boot.returncode == 0 and boot.stdout.strip() == "1":
                    boot_completed = True
                    break
            if proc.poll() is not None:
                break
            time.sleep(3)

        if not boot_completed or not serial:
            if log is not None:
                log.flush()
            log_tail = text_tail(log_path)
            venue_failure = emulator_venue_failure(log_tail)
            diagnostics: dict[str, Any] = {
                "emulator_log_tail": log_tail,
                "emulator_exit_code": proc.poll() if proc is not None else None,
                "serial": serial,
                "acceleration": accel_text[-2000:],
            }
            if serial:
                for prop in ("sys.boot_completed", "dev.bootcomplete", "init.svc.bootanim"):
                    probe = run(
                        [str(adb), "-s", serial, "shell", "getprop", prop],
                        env=env,
                        timeout=15,
                        check=False,
                    )
                    diagnostics[prop] = probe.stdout.strip() if probe.returncode == 0 else None
            if venue_failure:
                plan["status"] = "venue_limitation"
                plan["verification"] = {
                    "status": "venue_limitation",
                    "failure_type": venue_failure,
                    "verified_at": utcnow(),
                    **diagnostics,
                }
                atomic_json(plan_path, plan)
                receipt = base_receipt("verify", key, profile, state_root)
                receipt.update(
                    status="venue_limitation",
                    result_class="VENUE_LIMITATION",
                    failure_type=venue_failure,
                    next_action="use a venue exposing the profile's required native virtualization",
                )
                receipt["evidence"] = {"plan": str(plan_path), "toolchain_identity": identity, **diagnostics}
                write_receipt(state_root, receipt)
                return receipt, EXIT_VENUE
            raise AarHostError(
                "accelerated AVD did not complete boot",
                failure_type="avd_boot_failed",
                evidence=diagnostics,
            )

        play = run(
            [str(adb), "-s", serial, "shell", "pm", "path", "com.android.vending"],
            env=env,
            timeout=30,
            check=False,
        )
        api = run(
            [str(adb), "-s", serial, "shell", "getprop", "ro.build.version.sdk"], env=env
        ).stdout.strip()
        abi = run(
            [str(adb), "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], env=env
        ).stdout.strip()
        fingerprint = run(
            [str(adb), "-s", serial, "shell", "getprop", "ro.build.fingerprint"], env=env
        ).stdout.strip()

        if "package:" not in play.stdout:
            raise AarHostError(
                "fresh AVD booted without Google Play Store", failure_type="play_unavailable"
            )
        if api != "35" or abi != profile["image_abi"]:
            raise AarHostError(
                f"guest identity mismatch api={api} abi={abi}",
                failure_type="guest_identity_mismatch",
            )

        evidence = {
            "serial": serial,
            "boot_completed": True,
            "api_level": api,
            "abi": abi,
            "fingerprint": fingerprint,
            "play_store_present": True,
            "authenticated": False,
            "acceleration": accel_text[-2000:],
            "emulator_sudo_adapter": emulator_sudo,
        }
    finally:
        if log is not None:
            log.flush()
        stop_emulator_process(
            proc,
            serial=serial,
            adb=adb,
            env=env,
            os_name=profile["os"],
        )
        if log is not None:
            log.close()
        run([str(adb), "kill-server"], env=env, timeout=20, check=False)
        if emulator_sudo:
            ownership_restore = restore_runtime_ownership(runtime)

    if emulator_sudo and (not ownership_restore or not ownership_restore.get("passed")):
        raise AarHostError(
            "Linux KVM venue adapter could not restore project-local runtime ownership",
            failure_type="venue_adapter_cleanup_failed",
            exit_code=EXIT_VENUE,
            evidence={"ownership_restore": ownership_restore},
        )
    if ownership_restore is not None:
        evidence["ownership_restore"] = ownership_restore

    plan["status"] = "verified"
    plan["verified_at"] = utcnow()
    plan["verification"] = evidence
    atomic_json(plan_path, plan)

    receipt = base_receipt("verify", key, profile, state_root)
    receipt.update(
        status="verified",
        result_class="PASS",
        next_action=f"apply --plan {plan_path} to prove no-op, then cleanup",
    )
    receipt["evidence"] = {
        "plan": str(plan_path),
        "toolchain_identity": identity,
        "avd": evidence,
    }
    write_receipt(state_root, receipt)
    return receipt, 0


def stop_runtime_processes_windows(runtime: pathlib.Path) -> dict[str, Any]:
    """Terminate only processes executing binaries from this managed runtime."""
    if platform.system().casefold() != "windows":
        return {"attempted": False, "matched": [], "terminated": []}
    shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not shell:
        return {"attempted": True, "matched": [], "terminated": [], "error": "powershell_unavailable"}
    escaped = str(runtime.resolve()).replace("'", "''")
    command = (
        "$root='" + escaped + "';"
        "$p=Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase) };"
        "$out=@(); foreach($x in $p){"
        " try { Stop-Process -Id $x.ProcessId -Force -ErrorAction Stop; $out += [pscustomobject]@{Pid=$x.ProcessId;Path=$x.ExecutablePath;Stopped=$true} }"
        " catch { $out += [pscustomobject]@{Pid=$x.ProcessId;Path=$x.ExecutablePath;Stopped=$false;Error=$_.Exception.Message} }"
        "}; if($null -eq $out){'[]'} else {$out|ConvertTo-Json -Compress}"
    )
    cp = run([shell, "-NoProfile", "-NonInteractive", "-Command", command], check=False, timeout=60)
    try:
        value = json.loads(cp.stdout.strip() or "[]")
    except json.JSONDecodeError:
        value = []
    if isinstance(value, dict):
        value = [value]
    matched = value if isinstance(value, list) else []
    terminated = [item for item in matched if item.get("Stopped")]
    return {
        "attempted": True,
        "exit_code": cp.returncode,
        "matched": matched,
        "terminated": terminated,
        "stderr_tail": cp.stderr.strip()[-500:] or None,
    }


def cleanup(plan_path: pathlib.Path, state_root: pathlib.Path) -> dict[str, Any]:
    plan, _lock, key, profile, runtime = validate_plan(plan_path, state_root)
    if plan.get("status") not in {"applied", "verified", "venue_limitation"}:
        raise AarHostError(
            "cleanup requires applied, verified, or venue-limitation state",
            failure_type="invalid_state",
        )
    if runtime.is_symlink():
        raise AarHostError("refusing cleanup of symlink runtime root", failure_type="unsafe_cleanup")
    expected = (state_root / "runtime" / key).resolve()
    if runtime.resolve() != expected or runtime.parent.resolve() != (state_root / "runtime").resolve():
        raise AarHostError(
            "cleanup root failed fixed project-local check", failure_type="unsafe_cleanup"
        )
    process_cleanup = None
    if runtime.exists() and profile["os"] == "windows":
        process_cleanup = stop_runtime_processes_windows(runtime)
        # Give Windows a bounded interval to release executable/image handles.
        time.sleep(2)
    if runtime.exists():
        last_error: OSError | None = None
        for attempt in range(10):
            try:
                shutil.rmtree(runtime)
                last_error = None
                break
            except OSError as exc:
                last_error = exc
                if profile["os"] == "windows":
                    process_cleanup = stop_runtime_processes_windows(runtime)
                time.sleep(min(1 + attempt, 5))
        if last_error is not None and runtime.exists():
            raise last_error

    plan["cleanup"] = {
        "status": "removed",
        "at": utcnow(),
        "runtime_root": str(runtime),
    }
    atomic_json(plan_path, plan)

    receipt = base_receipt("cleanup", key, profile, state_root)
    receipt.update(status="cleaned", result_class="PASS", next_action="cycle complete")
    receipt["evidence"] = {
        "plan": str(plan_path),
        "runtime_removed": not runtime.exists(),
        "windows_runtime_process_cleanup": process_cleanup,
    }
    write_receipt(state_root, receipt)
    return receipt


def interface_contract() -> dict[str, Any]:
    lock = load_lock()
    return {
        "schema": "aar-play-host-interface/v1",
        "lifecycle": ["observe", "plan", "apply", "verify", "cleanup"],
        "audiences": {
            "human": {
                "default_format": "human",
                "behavior": "concise status + typed failure + next action",
            },
            "automation": {
                "format": "json",
                "receipt_schema": SCHEMA,
                "exit_codes": {
                    "0": "success",
                    str(EXIT_UNSUPPORTED): "unsupported_host",
                    str(EXIT_VENUE): "venue_limitation",
                    str(EXIT_FAILURE): "failure",
                },
                "idempotency": "second apply validates exact toolchain identity and returns no-op",
            },
            "agent": {
                "discover": "contract --format json",
                "observe": "observe --format json",
                "plan": "plan --accept-sdk-licenses --format json",
                "mutations": ["apply", "cleanup"],
                "verification": "verify",
                "authority_rule": "visibility/tool access never implies authority; apply requires an exact plan",
            },
        },
        "state": {
            "scope": "project-local",
            "plan_binding": ["lock_sha256", "implementation_sha256", "host_profile"],
            "credentials": "not materialized by this host bootstrap",
        },
        "supported_profiles": lock.get("profiles", {}),
        "unsupported_profiles": lock.get("unsupported", {}),
    }


def emit(receipt: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return
    host = receipt.get("host", {})
    label = host.get("profile") or f"{host.get('os')}-{host.get('architecture')}"
    bits = [f"AAR Play Host [{label}]", receipt.get("status", "unknown")]
    if receipt.get("failure_type"):
        bits.append(receipt["failure_type"])
    print(" | ".join(bits))
    if receipt.get("next_action"):
        print("next:", receipt["next_action"])


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-root", type=pathlib.Path, default=DEFAULT_STATE)
    p.add_argument("--format", choices=("human", "json"), default="human")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("contract")
    sub.add_parser("observe")
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--accept-sdk-licenses", action="store_true")
    for name in ("apply", "verify", "cleanup"):
        child = sub.add_parser(name)
        child.add_argument("--plan", type=pathlib.Path, required=True)
        if name == "verify":
            child.add_argument("--boot-timeout", type=int, default=300)
            child.add_argument(
                "--emulator-sudo",
                action="store_true",
                help="Linux hosted-runner adapter: elevate only emulator/KVM while ADB remains caller-owned",
            )
    return p


def main() -> int:
    args = parser().parse_args()
    state_root = args.state_root.resolve()
    try:
        if args.command == "contract":
            value = interface_contract()
            if args.format == "json":
                print(json.dumps(value, indent=2, sort_keys=True))
            else:
                profiles = ", ".join(sorted(value["supported_profiles"]))
                print("AAR Play Host interface | observe -> plan -> apply -> verify -> cleanup")
                print("supported:", profiles)
                print("automation/agents: use --format json; agents may call contract --format json")
            return 0
        if args.command == "observe":
            receipt = observe(state_root)
            emit(receipt, args.format)
            return EXIT_UNSUPPORTED if receipt["status"] == "unsupported_host" else 0
        if args.command == "plan":
            receipt = create_plan(state_root, args.accept_sdk_licenses)
            emit(receipt, args.format)
            return 0
        if args.command == "apply":
            receipt = apply(args.plan.resolve(), state_root)
            emit(receipt, args.format)
            return 0
        if args.command == "verify":
            receipt, code = verify(
                args.plan.resolve(),
                state_root,
                args.boot_timeout,
                emulator_sudo=args.emulator_sudo,
            )
            emit(receipt, args.format)
            return code
        if args.command == "cleanup":
            receipt = cleanup(args.plan.resolve(), state_root)
            emit(receipt, args.format)
            return 0
        raise AarHostError("unhandled command", failure_type="internal")
    except (AarHostError, OSError, zipfile.BadZipFile, tarfile.TarError, json.JSONDecodeError) as exc:
        lock = load_lock()
        try:
            key, profile = host_profile(lock)
        except AarHostError:
            key, profile = None, None
        failure_type = exc.failure_type if isinstance(exc, AarHostError) else "io_or_archive_error"
        exit_code = exc.exit_code if isinstance(exc, AarHostError) else EXIT_FAILURE
        receipt = base_receipt(args.command, key, profile, state_root)
        receipt.update(
            status="failed",
            result_class="FAIL",
            failure_type=failure_type,
            next_action="inspect receipt and durable evidence before retry",
        )
        receipt["evidence"]["error"] = str(exc)
        if isinstance(exc, AarHostError) and exc.evidence:
            receipt["evidence"].update(exc.evidence)
        write_receipt(state_root, receipt)
        emit(receipt, args.format)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
