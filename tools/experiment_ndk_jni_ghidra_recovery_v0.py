#!/usr/bin/env python3
"""A-3 source-known stripped JNI ELF Ghidra boundary/callgraph qualification.

The .so seen by Ghidra contains no hidden helper symbols. A private-to-run
producer-side llvm-nm symbol oracle checks entries *after* Ghidra's independent
callgraph observation. Only aggregate metadata is published. This is not a
semantic reversing-actor interview or new ART runtime qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from experiment_ndk_jni_bridge_v0 import CPP, JNI, ndk_root

ABIS={"x86_64":(62,"x86_64-linux-android35"),"aarch64":(183,"aarch64-linux-android35")}
SYMBOLS=("aar_fold","aar_affine")
def cmd(*args):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,
                          check=True,timeout=120).stdout
def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def build(root, abi, optimization="O1", fixture_kind="baseline"):
    if fixture_kind not in ("baseline", "controlflow"):
        raise ValueError("unadmitted source-owned native fixture")
    if fixture_kind == "controlflow":
        from experiment_ndk_jni_controlflow_v0 import CPP_CONTROL_FLOW
        fixture_cpp = CPP_CONTROL_FLOW
    else:
        fixture_cpp = CPP
    if optimization not in ("O0", "O1", "O2"):
        raise ValueError("unadmitted NDK optimizer treatment")
    if abi not in ABIS: raise ValueError("unknown ABI")
    root.mkdir(parents=True,exist_ok=True)
    ndk=ndk_root()
    bins=list((ndk/"toolchains/llvm/prebuilt").glob("*/bin/clang++"))
    if len(bins)!=1: raise ValueError("ambiguous pinned clang")
    bin=bins[0].parent
    cpp=root/"fixture.cpp"
    cpp.write_text(fixture_cpp,encoding="utf-8")
    unstripped=root/(abi+"-oracle-unstripped.so")
    stripped=root/(abi+"-ghidra-stripped.so")
    cmd(bin/"clang++","--target="+ABIS[abi][1],"-nostdlib++","-g","-"+optimization,
        "-fPIC","-fvisibility=hidden","-fno-exceptions","-ffunction-sections",
        "-fdata-sections","-shared","-Wl,--gc-sections","-Wl,--build-id=none",
        "-o",unstripped,cpp)
    symbol_text=cmd(bin/"llvm-nm","-a","--defined-only",unstripped)
    oracle={}
    for key in (*SYMBOLS,JNI):
        matches=[int(m.group(1),16) for line in symbol_text.splitlines()
                 if key in line and (m:=re.match(r"^([0-9a-fA-F]+)\s+\S\s+\S+",line))]
        if len(matches)!=1 or matches[0] == 0:
            raise ValueError("missing or duplicated producer-side symbol: "+key)
        oracle[key]=matches[0]
    if len(set(oracle.values()))!=3:raise ValueError("helper address alias")
    cmd(bin/"llvm-strip","--strip-all","-o",stripped,unstripped)
    data=stripped.read_bytes()
    if len(data)>10_000_000 or data[:5]!=b"\x7fELF\x02" or struct.unpack_from("<H",data,18)[0]!=ABIS[abi][0]:
        raise ValueError("wrong ELF machine or image size")
    if any(key.encode() in data for key in SYMBOLS):
        raise ValueError("hidden helper name leaked to stripped ELF")
    exports=cmd(bin/"llvm-nm","-D","--defined-only",stripped)
    if JNI not in exports or any(x in exports for x in SYMBOLS):
        raise ValueError("export identity or helper visibility failed")
    needed=cmd(bin/"llvm-readelf","-d",stripped)
    if "libc++_shared.so" in needed or "libc.so" not in needed:
        raise ValueError("native ABI dependency not self-contained for JNI fixture")
    receipt={"schema":1,"abi":abi,"elf_machine":ABIS[abi][0],
             "elf_sha256":digest(stripped),
             "cpp_sha256":hashlib.sha256(fixture_cpp.encode()).hexdigest(),
             "fixture_kind":fixture_kind,
             "ndk":"27.3.13750724","optimization":"-"+optimization,
             "jni_address":oracle[JNI],
             "helper_truth":{k:oracle[k] for k in SYMBOLS},
             "published":False}
    (root/(abi+"-private-oracle.json")).write_text(json.dumps(receipt,sort_keys=True))
    print("AAR_A3_BUILD="+json.dumps({"abi":abi,"elf_sha256":receipt["elf_sha256"],
        "elf_machine":receipt["elf_machine"],"source_sha256":receipt["cpp_sha256"],
        "private_helper_truth_not_published":True},sort_keys=True))

def evaluate(probe, oracle, elf, abi):
    if abi not in ABIS or oracle["abi"]!=abi or oracle["elf_machine"]!=ABIS[abi][0]:
        raise ValueError("cross-ABI comparison forbidden")
    if digest(elf)!=oracle["elf_sha256"]:
        raise ValueError("Ghidra input digest not bound to source oracle")
    def one(tag):
        values=re.findall(r"AAR_A3_"+tag+r"=([^\s]+)",probe)
        if len(values)!=1:raise ValueError("missing/duplicate Ghidra "+tag)
        return values[0]
    base=int(one("IMAGE_BASE"),16)
    if one("ABI")!=abi or int(one("JNI_ENTRY"),16)-base!=oracle["jni_address"]:
        raise ValueError("wrong recovered JNI export or ABI")
    observed={}
    for addr, count, decompiled in re.findall(r"AAR_A3_CALLEE=([0-9a-f]+)\|(\d+)\|(true|false)",probe):
        n=int(addr,16)-base
        if n in observed or int(count)<1:raise ValueError("duplicate/empty function")
        observed[n]=decompiled=="true"
    if len(observed)!=int(one("INTERNAL_CALLS")) or len(observed)>16:
        raise ValueError("callgraph cardinality mismatch")
    expected=set(oracle["helper_truth"].values())
    if len(expected)!=2 or set(observed)!=expected:
        raise ValueError("hidden JNI helper entries missing, extra, or misattributed")
    if not all(observed.values()):raise ValueError("one or more bodies not decompiled")
    return {"schema":1,"status":"A3_JNI_CALLGRAPH_BOUNDARY_PASS",
            "abi":abi,"elf_sha256":oracle["elf_sha256"],
            "helpers_identified_against_independent_symbol_truth":2,
            "decompiled_bodies":2,"source_oracle_exposed_to_ghidra":False,
            "runtime_semantics_newly_executed":False,
            "helper_semantics_independently_reconstructed":False,
            "actor_qualified":False,"arm64_art_runtime_qualified":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--abi",choices=ABIS,required=True)
    p.add_argument("--optimization",choices=("O0","O1","O2"),default="O1")
    p.add_argument("--fixture-kind",choices=("baseline","controlflow"),default="baseline")
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--build",action="store_true")
    g.add_argument("--verify",type=Path)
    a=p.parse_args()
    if a.build:build(a.root,a.abi,a.optimization,a.fixture_kind)
    else:
        oracle=json.loads((a.root/(a.abi+"-private-oracle.json")).read_text())
        result=evaluate(a.verify.read_text(errors="replace"),oracle,
                        a.root/(a.abi+"-ghidra-stripped.so"),a.abi)
        (a.root/(a.abi+"-a3-public-receipt.json")).write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print("AAR_A3_VERIFY="+json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try:main()
    except (ValueError,KeyError,OSError,subprocess.SubprocessError) as e:
        print("AAR_A3_FAIL="+str(e),file=sys.stderr)
        raise SystemExit(1)
