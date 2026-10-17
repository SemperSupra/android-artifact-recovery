# Stateless OCI tooling: cloud / sovereign parity

Status: draft PR #41, stacked on AAR draft #40. AAR-private #82 owns APK recovery, Model Spelunker #147 owns OCI actor realization/admission and #139 owns actor interviews; Agent Dispatch-private #104 owns actor task admission. This is an AAR **tool cell**, not a new actor model, scheduler, service, corpus store or OCI foundry.

## Architecture

The recovery tool images are disposable and stateless. Input APKs are read-only binds; evidence is the sole writable host bind. The capsule runs as an unprivileged identity with no network, read-only filesystem, dropped Linux capabilities, no Docker socket, no model secrets and bounded CPU, RAM, PIDs and ephemeral tmpfs. Build-time downloads are checked by SHA-256. The Dockerfile-specific ignore file excludes everything except public AAR tools, tests and capability contract. Do not embed private specimen bytes or per-user machine paths.

A single admitted OCI **registry manifest digest** is the shared image identity. Running the same immutable digest on the same architecture makes cloud/local tool bits identical. Building twice from the same Dockerfile is **not** automatically image identity: Debian package indexes can change, Docker rebuilds may differ, and image config IDs are not portable registry manifest IDs. Before claiming cross-host parity, independently retrieve the exact digest at both venues and compare capability observations.

## Profiles and boundaries

| Profile | Included capability | Venues | Excluded |
| --- | --- | --- | --- |
| python-core | Python 3.12 and existing AAR static characterization/admission/evidence tools | Native Linux OCI amd64 and arm64 | JADX/SDK/behavior |
| java-static | Python core, JRE 17, hash-pinned JADX 1.5.6, Apktool 3.0.3 | Native amd64 and arm64 **subject to tests** | Native Android SDK aapt2/D8/dexdump, Ghidra, AVD |
| sdk-amd64 (next) | Exact Android build-tools/SDK from verified package release and admitted license | Linux/amd64; arm64 may require emulation | Not built or accepted yet |
| native (later) | LLVM / Ghidra with Java 21, scoped headless budgets | Conditional workload | Not built or accepted yet |
| actor and models | Reuse already admitted Model Spelunker OCI harnesses and BigMac/TrueNAS endpoints | Separate qualifying task | Not bundled in AAR tool image |
| Android HIL | AVD / physical device / Bluetooth/USB | Separately admitted | Not assumed from hosted containers |

Linux containers on Windows run through Docker Desktop's Linux backend/WSL2, **not native Windows containers**. Apple M2 Ultra can run native linux/arm64 profiles; amd64 emulation is a separate substrate with its own performance. TrueNAS Docker engine/app access must be verified locally, not inferred.

The code compares stable tool paths, executable hashes, version outputs, the installed JADX JAR set, artifact hashes and detected architecture. A passing fingerprint proves *mechanical tool identity only*: it does not prove decompiler correctness, original source identity, native code recovery, installed split equivalence, or live Android behavior. Retain UNKNOWN.

## Construction and cloud acceptance

The public GitHub Actions matrix uses standard free hosted Linux amd64/arm64 nodes. It resolves the Python base via the committed multiarch registry digest from containers/aar-tools/toolchain.lock.json (not latest), builds each profile with pinned external release archives and tests the restricted capsule. Host launch and negative checks also run on hosted Windows, Linux and macOS. This spends no private hosted minutes, publishes no private target bytes, and grants no registry write permission.

The image build itself invokes Docker on a public ephemeral runner; the **tool process** is unprivileged and networkless. Existing Model Spelunker #147 rootless OCI packaging/admission can be reused for subsequent registry publication; no parallel foundry is introduced.

## Local commands

Use the source checkout including PR #40 and this stacked PR #41.

Linux / macOS bash:

    BASE=$(python3 -c 'import json; print(json.load(open("containers/aar-tools/toolchain.lock.json"))["base_image"])')
    docker build -f containers/aar-tools/Dockerfile --build-arg "BASE_IMAGE=$BASE" --target python-core -t aar-python-core:local .
    IMAGE=$(docker image inspect aar-python-core:local --format '{{.Id}}')
    python3 tools/aar_container_launch.py probe --image "$IMAGE"

Windows PowerShell with Docker Desktop running Linux containers:

    $base = (Get-Content .\containers\aar-tools\toolchain.lock.json -Raw | ConvertFrom-Json).base_image
    docker build -f .\containers\aar-tools\Dockerfile --build-arg "BASE_IMAGE=$base" --target python-core -t aar-python-core:local .
    $image = docker image inspect aar-python-core:local --format '{{.Id}}'
    py -3 .\tools\aar_container_launch.py probe --image $image
    py -3 .\tools\aar_container_launch.py run --image $image --artifact "C:\path\to\authorized-fixture.apk" --work-root "C:\path\to\aar-evidence"

The local SHA config ID addresses a particular built image on that local engine; a cross-host exact identity requires a registry/OCI manifest reference such as repository@sha256:<64 hex>, which is not published by this draft. The normal launcher refuses floating tags; CI-only testing can opt in explicitly. The --dry-run mode checks command construction without a running Docker engine or writing case data.

## Remaining gates

1. Verify latest exact GitHub Actions run on this PR; record pass, failure and skipped states without laundering any failure.
2. Qualify exact named JNI and Kotlin source-known recovery on the final containerized Android SDK profile, not on host assumptions.
3. Audit Java/JADX/Apktool licensing and downstream SDK redistribution, then reuse existing OCI foundry for immutable publication/admission if approved. Do not create automatic push on PR.
4. Execute local Windows/WSL2, TrueNAS x64 and BigMac arm64 image/run/mount preflights; compare exact image identities and functionally matched fixtures. Record emulation/performance separately.
5. Reuse Model Spelunker actor bindings, portable launch contracts and independent evaluators, preserving campaign-private artifact and model-gateway boundaries.
