#!/usr/bin/env python3
"""Bounded, author-owned Android ARM64 JNI -> Java class -> DEX provenance test.
No device/emulator execution and no SDK/NDK/vendor binaries in artifact.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CPP = r'''
#include <jni.h>
#include <stdint.h>
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_fold(uint32_t x) {
    x ^= 0x51ad70e5u;
    x *= 0x9e3779b1u;
    return (x << 9) | (x >> 23);
}
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_affine(uint32_t x) {
    return x * 17u + 0x07654321u;
}
extern "C" JNIEXPORT jint JNICALL
Java_org_sempersupra_aar_golden_NativeBridge_nativeDispatch(
    JNIEnv*, jclass, jint mode, jint value) {
    uint32_t v = (uint32_t)value;
    if (mode == 5) return (jint)aar_fold(v);
    if (mode == 7) return (jint)aar_affine(v);
    return (jint)0xffffffffu;
}
'''
JAVA = r'''
package org.sempersupra.aar.golden;
public final class NativeBridge {
    private NativeBridge() {}
    public static native int nativeDispatch(int mode, int value);
    public static int dispatch(int mode, int value) {
        return nativeDispatch(mode, value);
    }
}
'''
JNI="Java_org_sempersupra_aar_golden_NativeBridge_nativeDispatch"
CLASS="Lorg/sempersupra/aar/golden/NativeBridge;"
MAX=10_000_000

def sha(p:Path)->str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def run(cmd:list[str],limit=90)->str:
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=limit,check=True)
    return p.stdout

def ndk_root()->Path:
    candidates=[]
    for k in ("ANDROID_NDK_HOME","ANDROID_NDK_ROOT"):
        if os.getenv(k): candidates.append(Path(os.environ[k]))
    for k in ("ANDROID_HOME","ANDROID_SDK_ROOT"):
        if os.getenv(k): candidates.extend((Path(os.environ[k])/"ndk").glob("*"))
    for path in (Path("/usr/local/lib/android/sdk/ndk"),):
        candidates.extend(path.glob("*"))
    valid=[p.resolve() for p in candidates if (p/"source.properties").is_file()]
    if not valid:raise RuntimeError("NO_INSTALLED_ANDROID_NDK")
    valid=sorted(set(valid),reverse=True)
    exact=[x for x in valid if "27.3.13750724" in (x/"source.properties").read_text()]
    if not exact:raise RuntimeError("PINNED_NDK_R27C_NOT_AVAILABLE")
    return exact[0]

def android_home()->Path:
    candidates=[Path(os.environ[k]) for k in ("ANDROID_HOME","ANDROID_SDK_ROOT") if os.getenv(k)]
    candidates.append(Path("/usr/local/lib/android/sdk"))
    for p in candidates:
        if (p/"platforms"/"android-35"/"android.jar").is_file():return p
    raise RuntimeError("SDK_ANDROID_35_NOT_INSTALLED")

def dex_strings(path:Path)->set[str]:
    b=path.read_bytes()
    if len(b)<112 or not b.startswith(b"dex\n") or b[7]!=0: raise ValueError("invalid DEX magic")
    if struct.unpack_from("<I",b,32)[0]!=len(b) or struct.unpack_from("<I",b,36)[0]!=112:
        raise ValueError("bad DEX length/header")
    size,table=struct.unpack_from("<II",b,56)
    if not 1<=size<=10000 or table+4*size>len(b):raise ValueError("bad DEX string index")
    strings=set()
    for i in range(size):
        off=struct.unpack_from("<I",b,table+4*i)[0]
        if off>=len(b):raise ValueError("bad DEX string offset")
        # Skip variable-length UTF-16 count (one to five bytes).
        for j in range(5):
            v=b[off+j]
            if v<128:
                off=off+j+1
                break
        else:raise ValueError("invalid ULEB length")
        end=b.find(b"\x00",off,min(off+2048,len(b)))
        if end<0:raise ValueError("unterminated DEX string")
        strings.add(b[off:end].decode("utf-8"))
    return strings

def main():
    ndk=ndk_root()
    sdk=android_home()
    host=list((ndk/"toolchains/llvm/prebuilt").glob("*/bin/clang++"))
    if len(host)!=1:raise RuntimeError("AMBIGUOUS_NDK_CLANG")
    bin=host[0].parent
    d8=sorted((sdk/"build-tools").glob("*/d8"),reverse=True)
    if not d8:raise RuntimeError("ANDROID_D8_NOT_INSTALLED")
    javac=shutil.which("javac")
    if not javac:raise RuntimeError("JAVA_COMPILER_MISSING")
    with tempfile.TemporaryDirectory(prefix="aar-ndk-jni-v0-") as work:
        root=Path(work)
        cpp=root/"native_bridge.cpp"
        java=root/"org/sempersupra/aar/golden/NativeBridge.java"
        java.parent.mkdir(parents=True)
        cpp.write_text(CPP,encoding="utf-8")
        java.write_text(JAVA,encoding="utf-8")
        lib=root/"libaar_jni_v0.so"
        run([str(bin/"clang++"),"--target=aarch64-linux-android35",
             "-O1","-fPIC","-fvisibility=hidden","-fno-exceptions",
             "-ffunction-sections","-fdata-sections","-shared","-Wl,--gc-sections",
             "-Wl,--build-id=none","-o",str(lib),str(cpp)])
        if not 0 < lib.stat().st_size < MAX:raise ValueError("native ELF invalid size")
        data=lib.read_bytes()
        if data[:4]!=b"\x7fELF" or data[4]!=2 or struct.unpack_from("<H",data,18)[0]!=183:
            raise ValueError("JNI library not ARM64 ELF64")
        nm=run([str(bin/"llvm-nm"),"-D","--defined-only",str(lib)])
        exported={line.split()[-1] for line in nm.splitlines() if line.strip()}
        if JNI not in exported:raise ValueError("JNI export missing")
        if any("aar_fold" in name or "aar_affine" in name for name in exported):
            raise ValueError("hidden private helpers exposed")
        classes=root/"classes"
        classes.mkdir()
        run([javac,"-source","8","-target","8","-d",str(classes),str(java)])
        clazz=classes/"org/sempersupra/aar/golden/NativeBridge.class"
        dexdir=root/"dex"
        dexdir.mkdir()
        run([str(d8[0]),"--lib",str(sdk/"platforms/android-35/android.jar"),
             "--min-api","35","--output",str(dexdir),str(clazz)],limit=120)
        dex=dexdir/"classes.dex"
        strings=dex_strings(dex)
        if CLASS not in strings or "nativeDispatch" not in strings or "dispatch" not in strings:
            raise ValueError("DEX bridge identity missing")
        # DEX class_defs_size offset 96, method_ids_size offset 88
        classes_count=struct.unpack_from("<I",dex.read_bytes(),96)[0]
        method_count=struct.unpack_from("<I",dex.read_bytes(),88)[0]
        if classes_count<1 or method_count<2:raise ValueError("DEX method/class table unexpectedly empty")
        # Bounded receipt only. Source exists in this tool under version control.
        receipt={"schema_version":1,"status":"NDK_JNI_ARM64_DEX_STATIC_PROVENANCE_PASS",
          "ndk_revision":"27.3.13750724","sdk_api":35,"abi":"arm64-v8a",
          "jni_export":JNI,"private_helper_names_not_exported":True,
          "source_digest":hashlib.sha256((CPP+JAVA).encode()).hexdigest(),
          "elf_sha256":sha(lib),"elf_bytes":lib.stat().st_size,
          "class_sha256":sha(clazz),"dex_sha256":sha(dex),"dex_bytes":dex.stat().st_size,
          "dex_class_defs":classes_count,"dex_method_ids":method_count,
          "javac_version":run([javac,"-version"]).strip() if False else "JDK_FROM_RUNNER",
          "llvm_clang_version":run([str(bin/"clang++"),"--version"]).splitlines()[0],
          "native_runtime_executed":False,"emulator_qualified":False,
          "libcxx_reference_matches":0,
          "result_scope":"STATIC_BINARY_AND_JNI_DEX_CROSSWALK_ONLY",
          "sdk_ndk_binary_artifacts_uploaded":False}
        dest=Path(os.environ.get("RUNNER_TEMP",str(root)))/"aar-ndk-jni-v0.json"
        dest.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
        print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":
    try:main()
    except (RuntimeError,ValueError,OSError,subprocess.SubprocessError) as exc:
        print("NDK_JNI_PROBE_FAIL="+str(exc),file=sys.stderr)
        raise SystemExit(1)
