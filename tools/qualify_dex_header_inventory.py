#!/usr/bin/env python3
"""Independent bounded static root-DEX header census; no code contents published."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

NAME = re.compile(r"^classes(?:[2-9][0-9]*)?\.dex$")
MAGIC = re.compile(rb"^dex\n[0-9]{3}\x00$")
TABLES = {"string_ids":(56,4), "type_ids":(64,4), "proto_ids":(72,12),
          "field_ids":(80,8), "method_ids":(88,8), "class_defs":(96,32)}
MAX_DEX = 32
MAX_MEMBERS = 100000
MAX_DEX_BYTES = 250 * 1024 * 1024

def read_header(header: bytes, declared_size: int) -> dict:
    if len(header) != 112 or not MAGIC.fullmatch(header[:8]):
        raise ValueError("invalid DEX magic or header length")
    length, size, endian = struct.unpack_from("<III", header, 32)
    if length != declared_size or size != 112 or endian != 0x12345678:
        raise ValueError("DEX header size/endian mismatch")
    counts = {}
    for key, (offset, stride) in TABLES.items():
        n, start = struct.unpack_from("<II", header, offset)
        if (n and (start < 112 or start > length or n * stride > length - start)) or (not n and start):
            raise ValueError("out-of-bounds DEX table " + key)
        counts[key] = n
    return {"dex_version":header[4:7].decode("ascii"),
            "file_size_bytes":length,
            "header_sha256":hashlib.sha256(header).hexdigest(), **counts}

def census(apk: Path) -> dict:
    if not zipfile.is_zipfile(apk):
        raise ValueError("not a ZIP-compatible APK")
    rows = []
    with zipfile.ZipFile(apk) as zf:
        members = zf.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("APK entry bound exceeded")
        dex = [i for i in members if NAME.fullmatch(i.filename)]
        if not dex or len(dex) > MAX_DEX:
            raise ValueError("missing or excessive root DEX entries")
        if len({i.filename.casefold() for i in dex}) != len(dex):
            raise ValueError("duplicate root DEX names")
        for info in sorted(dex,key=lambda i:i.filename):
            if info.is_dir() or not 112 <= info.file_size <= MAX_DEX_BYTES:
                raise ValueError("invalid DEX declared size")
            with zf.open(info) as fp:
                data = fp.read(112)
            rows.append({"root_dex_name":info.filename,
                         **read_header(data, info.file_size)})
    return {"schema":"aar-derived-dex-header-census/v1",
            "evidence_grade":"STATIC_HEADER_COUNTERS_ONLY",
            "root_dex_count":len(rows),
            "aggregate":{k:sum(x[k] for x in rows) for k in TABLES},
            "dex_headers":rows,
            "payload_crc_verified":False,
            "java_source_coverage":"NOT_ESTABLISHED",
            "runtime_qualified":False,
            "claim_boundary":"DEX class_defs and method_ids counts are independent bytecode header cardinalities, not JADX source recovery or execution."}

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    r=census(a.apk)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"schema":r["schema"],"root_dex_count":r["root_dex_count"],
                      "aggregate":r["aggregate"],"runtime_qualified":False},sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
