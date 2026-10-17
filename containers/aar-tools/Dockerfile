# Stateless AAR tool execution capsule; one Linux OCI contract for GHA and local.
# Resolve BASE_IMAGE to a fully qualified registry digest in CI/local build.
# No local AI model, credentials, APK corpus, Docker socket, or service endpoints are embedded.
ARG BASE_IMAGE=docker.io/library/python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
FROM ${BASE_IMAGE} AS python-core
LABEL org.opencontainers.image.source="https://github.com/SemperSupra/android-artifact-recovery" \
      org.opencontainers.image.title="AAR stateless tools (Python core)" \
      org.opencontainers.image.description="Synthetic/public Android artifact admission and characterization; no semantic recovery claims"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
WORKDIR /opt/aar
COPY tools/ /opt/aar/tools/
COPY tests/ /opt/aar/tests/
COPY containers/aar-tools/parity-contract.json /opt/aar/parity-contract.json
# Numeric unprivileged identity. Runtime is additionally --read-only --network none --cap-drop ALL.
USER 65532:65532
CMD ["python", "tools/aar_image_parity.py", "probe", "--profile", "python-core"]

# JVM APK resource / decompilation tools. No Android SDK native executables are assumed.
# Exact download hashes independently established by prior AAR public source-known GHA reps.
FROM python-core AS java-static
USER 0:0
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
ARG JADX_ZIP_SHA256=545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974
ARG APKTOOL_JAR_SHA256=dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423
RUN set -eux; \
    curl --fail --location --retry 3 --max-time 120 \
      https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
      -o /tmp/jadx.zip; \
    echo "$JADX_ZIP_SHA256  /tmp/jadx.zip" | sha256sum -c -; \
    mkdir -p /opt/jadx; unzip -q /tmp/jadx.zip -d /opt/jadx; rm /tmp/jadx.zip; \
    curl --fail --location --retry 3 --max-time 120 \
      https://github.com/iBotPeaches/Apktool/releases/download/v3.0.3/apktool_3.0.3.jar \
      -o /opt/apktool-3.0.3.jar; \
    echo "$APKTOOL_JAR_SHA256  /opt/apktool-3.0.3.jar" | sha256sum -c -; \
    printf '#!/bin/sh\nexec java -jar /opt/apktool-3.0.3.jar "$@"\n' > /usr/local/bin/apktool; \
    chmod 0755 /usr/local/bin/apktool; \
    /opt/jadx/bin/jadx --version; /usr/local/bin/apktool --version
ENV PATH="/opt/jadx/bin:${PATH}" JADX=/opt/jadx/bin/jadx APKTOOL=/usr/local/bin/apktool \
    JAVA_TOOL_OPTIONS="-Duser.home=/tmp" XDG_CONFIG_HOME=/tmp/.config \
    XDG_DATA_HOME=/tmp/.local/share
USER 65532:65532
CMD ["python", "tools/aar_image_parity.py", "probe", "--profile", "java-static"]

# Deliberately NOT in this image:
# - Android SDK native build-tools (aapt2, dexdump, apksigner): separate sdk-amd64 profile
#   pending exact SDK archive/package identities and redistribution/license decision.
# - Ghidra/LLVM native suite: separate large native-analysis profile with JDK 21.
# - AVD/KVM/ADB live device state: independently admitted HIL substrate.
# - Goose/OpenWorker/agent models: separately admitted Model Spelunker harness artifacts.
