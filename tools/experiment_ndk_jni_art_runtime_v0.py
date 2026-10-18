#!/usr/bin/env python3
"""AAR A-2: disposable x86_64 Android ART/JNI semantic control.

This is a deliberately *separate ABI treatment* of the already admitted ARM64
reference source. GHA host evaluator knows expected vectors; the Android runtime
receives only DEX, JNI library and probe arguments, never the oracle truth.
No Android APK/device, credentials, network service, or actor harness required.
"""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, struct, subprocess, sys, zipfile
from pathlib import Path
from experiment_ndk_jni_bridge_v0 import CPP, JAVA, JNI, ndk_root, android_home, dex_strings, run, sha

MAIN=r'''
package org.sempersupra.aar.golden;
public final class RuntimeProbe {
    static { System.load("/data/local/tmp/aar_a2_native.so"); }
    public static void main(String[] args) {
        int[] modes={5,5,5,5,7,7,7,19};
        int[] vals={0,1,-1,0x12345678,0,1,-7,42};
        for (int i=0;i<modes.length;i++) {
            int actual=NativeBridge.dispatch(modes[i],vals[i]);
            System.out.println("AAR_A2_VECTOR="+i+","+modes[i]+","+vals[i]+","+actual);
        }
    }
}
'''

def cmd(argv:list[str],timeout=120)->str:
    p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,check=True)
    return p.stdout

def produce(root:Path)->None:
    root.mkdir(parents=True,exist_ok=True)
    ndk=ndk_root()
    sdk=android_home()
    toolchains=list((ndk/"toolchains/llvm/prebuilt").glob("*/bin/clang++"))
    if len(toolchains)!=1:raise ValueError("NDK compiler count != 1")
    bindir=toolchains[0].parent
    compiler=bindir/"clang++"
    javac=shutil.which("javac")
    if not javac:raise ValueError("javac missing")
    d8s=sorted((sdk/"build-tools").glob("*/d8"),reverse=True)
    if not d8s:raise ValueError("d8 missing")
    cpp=root/"native_bridge.cpp"
    cpp.write_text(CPP)
    native=root/"aar_a2_native.so"
    cmd([str(compiler),"--target=x86_64-linux-android35",
         "-O1","-fPIC","-fvisibility=hidden","-fno-exceptions",
         "-ffunction-sections","-fdata-sections","-shared",
         "-Wl,--gc-sections","-Wl,--build-id=none",
         "-o",str(native),str(cpp)])
    header=native.read_bytes()
    if not header.startswith(b"\x7fELF") or header[4]!=2 or struct.unpack_from("<H",header,18)[0]!=62:
        raise ValueError("not ELF64 x86_64")
    symbols=cmd([str(bindir/"llvm-nm"),"-D","--defined-only",str(native)])
    if JNI not in symbols or "aar_fold" in symbols or "aar_affine" in symbols:
        raise ValueError("JNI export identity or helper visibility failure")
    package=root/"org/sempersupra/aar/golden"
    package.mkdir(parents=True,exist_ok=True)
    java=package/"NativeBridge.java"
    probe=package/"RuntimeProbe.java"
    java.write_text(JAVA)
    probe.write_text(MAIN)
    classes=root/"classes"
    classes.mkdir(exist_ok=True)
    cmd([javac,"-source","8","-target","8","-d",str(classes),str(java),str(probe)])
    dexout=root/"dex"
    dexout.mkdir(exist_ok=True)
    classfiles=sorted(str(p) for p in classes.rglob("*.class"))
    cmd([str(d8s[0]),"--lib",str(sdk/"platforms/android-35/android.jar"),
         "--min-api","35","--output",str(dexout),*classfiles])
    dex=dexout/"classes.dex"
    words=dex_strings(dex)
    for word in ("Lorg/sempersupra/aar/golden/NativeBridge;",
                 "Lorg/sempersupra/aar/golden/RuntimeProbe;",
                 "nativeDispatch"):
        if word not in words:raise ValueError("DEX missing bridge/probe "+word)
    jar=root/"aar_a2.dex.jar"
    with zipfile.ZipFile(jar,"w",compression=zipfile.ZIP_STORED) as out:
        out.write(dex,arcname="classes.dex")
    receipt={"schema_version":1,"status":"A2_X86_64_SEPARATE_ABI_BUILD_PASS",
             "ndk":"27.3.13750724","android_api":35,
             "elf_sha256":sha(native),"dex_sha256":sha(dex),
             "jar_sha256":sha(jar),"elf_machine":62,
             "source_cpp_sha256":hashlib.sha256(CPP.encode()).hexdigest(),
             "source_java_sha256":hashlib.sha256(JAVA.encode()).hexdigest(),
             "abi":"x86_64","jni_export":JNI,
             "runtime_executed":False}
    (root/"build-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("AAR_A2_BUILD="+json.dumps(receipt,sort_keys=True))

def expected(mode:int,val:int)->int:
    u=val&0xffffffff
    if mode==5:
        x=((u^0x51ad70e5)*0x9e3779b1)&0xffffffff
        result=((x<<9)|(x>>23))&0xffffffff
    elif mode==7:
        result=(u*17+0x07654321)&0xffffffff
    else:
        result=0xffffffff
    return result-(1<<32) if result>=(1<<31) else result

def execute(root:Path)->None:
    build=json.loads((root/"build-receipt.json").read_text())
    native=root/"aar_a2_native.so"
    jar=root/"aar_a2.dex.jar"
    if sha(native)!=build["elf_sha256"] or sha(jar)!=build["jar_sha256"]:
        raise ValueError("runtime inputs don't match qualified build manifest")
    serial=cmd(["adb","devices"],15)
    devices=[x for x in serial.splitlines() if "\tdevice" in x]
    if len(devices)!=1:raise ValueError("expected one disposable Android emulator")
    abi=cmd(["adb","shell","getprop","ro.product.cpu.abi"],15).strip()
    api=cmd(["adb","shell","getprop","ro.build.version.sdk"],15).strip()
    if abi!="x86_64" or api!="35":
        raise ValueError("emulator ABI/API mismatch "+abi+"/"+api)
    cmd(["adb","push",str(native),"/data/local/tmp/aar_a2_native.so"],30)
    cmd(["adb","push",str(jar),"/data/local/tmp/aar_a2.dex.jar"],30)
    cmd(["adb","shell","chmod","644","/data/local/tmp/aar_a2_native.so","/data/local/tmp/aar_a2.dex.jar"],20)
    # app_process loads classes.dex from archive via CLASSPATH; ART executes the
    # native bridge. Only return vectors cross the trust boundary.
    process=subprocess.run(
        ["adb","shell","env","CLASSPATH=/data/local/tmp/aar_a2.dex.jar",
         "app_process","/system/bin","org.sempersupra.aar.golden.RuntimeProbe"],
        capture_output=True,text=True,timeout=90,check=True)
    lines=process.stdout.splitlines()
    matches=re.findall(r"^AAR_A2_VECTOR=(\d+),(-?\d+),(-?\d+),(-?\d+)$",process.stdout,re.M)
    vectors=[(5,0),(5,1),(5,-1),(5,0x12345678),
             (7,0),(7,1),(7,-7),(19,42)]
    if len(matches)!=len(vectors):
        raise ValueError("ART result count mismatch "+str(len(matches)))
    for index,(m,v) in enumerate(vectors):
        row=tuple(map(int,matches[index]))
        if row!=(index,m,v,expected(m,v)):
            raise ValueError("ART semantic mismatch for vector "+str(index))
    proof={"schema_version":1,"status":"A2_ANDROID_ART_JNI_RUNTIME_PASS",
           "ndk":build["ndk"],"abi":abi,"api":int(api),
           "elf_sha256":build["elf_sha256"],"dex_sha256":build["dex_sha256"],
           "vectors_evaluated":len(vectors),"vectors_passed":len(matches),
           "native_runtime_executed":True,"independent_python_oracle":True,
           "physical_device_used":False,"actor_qualified":False,
           "android_fid_qualified":False,
           "emulator_kvm":Path("/dev/kvm").exists()}
    out=Path(os.environ.get("RUNNER_TEMP",str(root)))/"aar-a2-runtime-receipt.json"
    out.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    print("AAR_A2_RUNTIME="+json.dumps(proof,sort_keys=True))
    # Cleanup does not affect the emulator outside this disposable workcell.
    cmd(["adb","shell","rm","-f","/data/local/tmp/aar_a2_native.so",
         "/data/local/tmp/aar_a2.dex.jar"],15)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--build",action="store_true")
    g.add_argument("--run-emulator",action="store_true")
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    try:
        if a.build:produce(a.root)
        else:execute(a.root)
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as ex:
        print("AAR_A2_FAIL="+repr(ex),file=sys.stderr)
        sys.exit(1)
