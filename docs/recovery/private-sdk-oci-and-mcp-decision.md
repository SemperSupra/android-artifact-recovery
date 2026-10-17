# Private SDK OCI and MCP decision — 2026-10-17

## Authority and intended use

Android Artifact Recovery private #82 controls recovery methodology and corpus rights. Connected Device Recovery owns device/account authorization. Model Spelunker #147 owns actor OCI realization; #139 and Agent Dispatch-private #104 own actor qualification. This work introduces no second runner, scheduler, generic shell server, model gateway, or actor foundry.

## A private self-contained SDK image can be built — with conditions

The new PRIVATE/EPHEMERAL Dockerfile imports a **host-preinstalled, byte-verified Linux Android SDK** from a curated external build context and adds it to the previously cloud-qualified Java/JADX/Apktool OCI layer. It does not invoke sdkmanager, accept licenses, retrieve authentication, download SDK packages, or publish the resulting image.

Google's SDK terms generally restrict copying other than backup and redistribution (subject to particular open-source/third-party license exceptions). A private registry does not change that grant. This is an engineering feasibility path: the license/redistribution gate remains **HOLD** for GHCR or cross-organization transfers. If terms do not permit an image copy, use a separately installed, read-only SDK bind mount rather than publishing the embedded binaries.

Tools: tools/aar_sdk_stage.py, containers/aar-tools/Dockerfile.sdk-private, parity-contract.json sdk-mounted profile, and public GHA private-sdk-ephemeral qualification. Linux build-tools 37.0.0 and platform android-35 only. Exact AAPT2, apksigner, dexdump SHA256 from previously executed authored public AAR goldens; d8 and android.jar independently hashed during stage. Refuse symlinks, mutated tools, non-Linux/amd64 input, output collision and directory overlap; no license files/emulators/sources/user home packaged by the staging script. The Dockerfile uses an empty default context; only the explicit SDK input carries selected package bytes.

### Reproduce on a Linux x64 host with its own installed Linux SDK

    BASE=$(python3 -c 'import json; print(json.load(open("containers/aar-tools/toolchain.lock.json"))["base_image"])')
    docker build -f containers/aar-tools/Dockerfile --target java-static --build-arg "BASE_IMAGE=$BASE" -t aar-java-static:local .
    STAGE="$(mktemp -d)/sdk-input"
    python3 tools/aar_sdk_stage.py --sdk-root "$ANDROID_HOME" --output "$STAGE"
    docker build -f containers/aar-tools/Dockerfile.sdk-private --build-arg BASE_IMAGE=aar-java-static:local --build-context "sdk_input=$STAGE" -t aar-sdk-private:local .
    docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory 3g --tmpfs /tmp:rw,nosuid,size=256m --user 65532:65532 aar-sdk-private:local python tools/aar_image_parity.py probe --profile sdk-mounted

Use the installed Linux SDK *inside WSL2* if operating from Windows. Windows Android SDK .exe and Darwin SDK binaries are not Linux toolchain equivalents. On BigMac arm64, this x64 SDK image would require a separately validated amd64 Linux emulation substrate; the base Java tool image already has native arm64 tests. No current local-host execution is claimed.

The local tag is only a disposable local artifact; a cross-machine immutable manifest reference and capability receipts are required to claim exact hosted/local image parity. Never push or transfer this image merely because GHCR supports private packages. Remove local SDK staging once the test ends.

### Public GHA execution — not SDK redistribution

One ephemeral hosted Linux/amd64 job stages its runner-installed SDK, builds the unpushed image, probes all expected tool identities in a read-only networkless container, independently builds the source-known Kotlin APK, then runs existing AAR dexdump/JADX static recovery against that APK **inside the SDK image**. It destroys the image and SDK staging; no SDK-containing artifact, image or registry package is published. Nonzero JADX with generated files is explicitly PARTIAL, not full source equivalence. If dependencies/licenses/tools drift, the job must fail. CI artifacts should contain no copied SDK bytes.

## MCP is not a prerequisite

For headless AAR, no MCP servers are required. Android SDK CLIs, JADX, Apktool, dexdump, Gradle, LLVM and Ghidra analyzeHeadless already fit bounded subprocess/typed-receipt orchestration and source-known independent validators. Per-tool MCP services would add network exposure, scheduling and persistent state without improving objective correctness.

Candidates only where a measurable capability is missing:

1. Ghidra interactive JNI/native exploration: GhidraMCP (https://github.com/bethington/ghidra-mcp) offers headless/GUI function enumeration, cross references, decompilation and stateful analysis. Qualify a **small read-only** tool projection (get_metadata, list_methods, get_entry_points, decompile_function), with fixed binary SHA and permission checks at the service itself. Deny scripts, shell, write/rename and arbitrary path access. Avoid direct REST bypass of an MCP allowlist. Authenticated loopback/UDS or stdio only.
2. JADX GUI analyst session: the 0xdad0 project (https://github.com/0xdad0/jadx-mcp) supports class/source/reference browsing for JADX GUI 1.5.6. It explicitly lacks headless CLI operation and its HTTP listener has no auth. Treat as optional local interactive research, not cloud infrastructure; keep it on loopback and not on a shared machine without further controls.
3. CDR runtime ADB/Frida/device actions: a narrow existing local typed actuator behind CDR device/account/task grants, not a generic unrestricted device MCP server. Read-only evidence first, separate mutation/admission gates.
4. Generic tool wrappers and arbitrary shell/file-system MCP: NOT RECOMMENDED. The existing Model Spelunker actor/tool projection already provides the needed interface.

Use a paired source-known JNI golden to show that Ghidra MCP actually improves independent oracle success versus direct Ghidra scripts at comparable cost. Include prompt injection in decompiled strings, false symbol matches, concurrent queries, path traversal and attempts at unapproved write/script execution. Only add the server if the measured gain justifies its lifecycle, security review and deployment burden.

Decisions: NO_MCP_REQUIRED for base AAR; GHIDRA_MCP_READ_ONLY_CANDIDATE; JADX_GUI_MCP_RESEARCH_ONLY; CDR_DEVICE_MCP_HOLD.

Licensing source: https://developer.android.com/studio/terms
