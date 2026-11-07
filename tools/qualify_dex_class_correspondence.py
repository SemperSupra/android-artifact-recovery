#!/usr/bin/env python3
"""Bounded DEX class descriptor → JADX .java filename correspondence witness.

AOSP DEX format: class_def_item.class_idx → type_id.descriptor_idx →
string_id.string_data_off → uleb128 length + modified UTF-8 string.
Read original signed APK only on ephemeral runner. Emit aggregate counts only,
never class descriptors, Java filenames, class hashes, or recovered source.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import struct
import zipfile

from tools.qualify_dex_header_inventory import read_header, MAX_DEX_BYTES, census

MAX_CLASSES = 200_000
MAX_DESCR_BYTES = 4_096
SAFE_DESC = re.compile(rb"^L([A-Za-z0-9_/$]+);$")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("DEX index outside verified byte range")
    return struct.unpack_from("<I", data, offset)[0]


def _uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for i in range(5):
        if offset+i >= len(data):
            raise ValueError("truncated DEX uleb128")
        byte = data[offset+i]
        value |= (byte & 0x7f) << (7*i)
        if not byte & 0x80:
            if value > 0xffffffff:
                raise ValueError("DEX uleb128 overflow")
            return value, offset+i+1
    raise ValueError("DEX uleb128 exceeds 32bit length")


def _descriptor(data: bytes, class_idx: int, type_ids: tuple[int,int],
                string_ids: tuple[int,int]) -> bytes | None:
    typ_count,typ_off=type_ids
    str_count,str_off=string_ids
    if class_idx >= typ_count:
        raise ValueError("class_idx points beyond type_ids")
    descriptor_idx=_u32(data,typ_off+4*class_idx)
    if descriptor_idx >= str_count:
        raise ValueError("descriptor_idx points beyond string_ids")
    off=_u32(data,str_off+4*descriptor_idx)
    if off < 112 or off >= len(data):
        raise ValueError("string data offset outside DEX")
    utf16_len,start=_uleb(data,off)
    if utf16_len > MAX_DESCR_BYTES:
        return None
    stop=data.find(b"\x00",start,min(len(data),start+MAX_DESCR_BYTES+1))
    if stop < 0:
        raise ValueError("unterminated bounded DEX class descriptor")
    raw=data[start:stop]
    # MUTF-8 can contain multibyte UTF-16 code units. Abstain on these
    # rather than guessing a name or exporting a potentially sensitive string.
    if any(byte >= 128 for byte in raw):
        return None
    if len(raw) != utf16_len:
        raise ValueError("ASCII descriptor UTF-16 length mismatch")
    return raw


def qualify_dex(dex: bytes, output_sources: Path) -> dict:
    if len(dex)>MAX_DEX_BYTES:
        raise ValueError("DEX over byte budget")
    header=read_header(dex[:112],len(dex))
    count=header["class_defs"]
    if count>MAX_CLASSES:
        raise ValueError("DEX class count over budget")
    class_count,class_off=struct.unpack_from("<II",dex,96)
    type_ids=struct.unpack_from("<II",dex,64)
    string_ids=struct.unpack_from("<II",dex,56)
    if class_count!=count:
        raise ValueError("class table changed during parse")
    stats={
        "exact_top_level_file":0,
        "top_level_without_exact_file":0,
        "dollar_named_own_file":0,
        "dollar_named_parent_file_only":0,
        "dollar_named_without_correspondence":0,
        "non_ascii_or_unhandled_descriptor":0,
        "invalid_ascii_descriptor":0,
    }
    seen=set()
    for idx in range(count):
        class_idx=_u32(dex,class_off+32*idx)
        desc=_descriptor(dex,class_idx,type_ids,string_ids)
        if desc is None:
            stats["non_ascii_or_unhandled_descriptor"]+=1
            continue
        match=SAFE_DESC.fullmatch(desc)
        if not match:
            stats["invalid_ascii_descriptor"]+=1
            continue
        name=match.group(1).decode("ascii")
        if name in seen:
            raise ValueError("duplicate DEX class descriptor")
        seen.add(name)
        exact=output_sources/(name+".java")
        if "$" not in name:
            stats["exact_top_level_file" if exact.is_file() else
                  "top_level_without_exact_file"]+=1
        elif exact.is_file():
            stats["dollar_named_own_file"]+=1
        elif (output_sources/(name.split("$",1)[0]+".java")).is_file():
            stats["dollar_named_parent_file_only"]+=1
        else:
            stats["dollar_named_without_correspondence"]+=1
    if sum(stats.values())!=count:
        raise ValueError("classification cardinality invariant failed")
    return {"dex_class_defs":count,"observed_correspondence":stats}


def evaluate(apk: Path, jadx_root: Path, targets: tuple[str,...]) -> dict:
    if not 1<=len(targets)<=2 or len(set(targets))!=len(targets):
        raise ValueError("only 1-2 distinct DEX targets permitted")
    # Reject untrusted target paths before even opening an archive.
    if any(not re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",name) for name in targets):
        raise ValueError("unreviewed DEX target name")
    # Verify the *whole* signed archive's root-Dex presence, contiguity,
    # duplicate member bounds and actual DEX headers before resolving
    # filenames through a ZIP library that otherwise selects the last
    # occurrence of duplicate member names.
    root_census=census(apk)
    verified_names={x["root_dex_name"] for x in root_census["dex_headers"]}
    if not set(targets).issubset(verified_names):
        raise ValueError("target missing from verified original DEX census")
    results=[]
    with zipfile.ZipFile(apk) as z:
        for name in targets:
            if not re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",name):
                raise ValueError("unreviewed DEX target name")
            info=z.getinfo(name)
            if not 112<=info.file_size<=MAX_DEX_BYTES:
                raise ValueError("bad target DEX size")
            with z.open(info) as fp:
                data=fp.read(MAX_DEX_BYTES+1)
            if len(data)!=info.file_size:
                raise ValueError("DEX original length mismatch")
            idx=1 if name=="classes.dex" else int(name[7:-4])
            observed=qualify_dex(data,jadx_root/("shard-"+str(idx).zfill(2))/"sources")
            results.append({"root_dex_index":idx,**observed})
    totals={k:sum(r["observed_correspondence"][k] for r in results)
            for k in results[0]["observed_correspondence"]}
    return {
        "schema":"aar-derived-dex-class-path-correspondence/v1",
        "status":"BOUNDED_NAME_TO_FILE_PATH_CORRESPONDENCE_NOT_CLASS_COVERAGE",
        "targets_count":len(results),
        "total_target_class_defs":sum(r["dex_class_defs"] for r in results),
        "aggregate":totals,
        "shards":results,
        "original_app_executed":False,
        "complete_class_coverage_verified":False,
        "claim_boundary":"Exact filename correlation is not compilation or semantic decompilation proof. Decompiled aliases, folded inner classes and omitted files cause false negatives. No descriptors or filenames are published.",
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",type=Path,required=True)
    p.add_argument("--jadx-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--target",action="append",required=True)
    a=p.parse_args()
    result=evaluate(a.apk,a.jadx_root,tuple(a.target))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"schema":result["schema"],"status":result["status"],
                     "targets_count":result["targets_count"],
                     "total_target_class_defs":result["total_target_class_defs"]},sort_keys=True))


if __name__=="__main__":
    main()
