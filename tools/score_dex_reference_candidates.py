#!/usr/bin/env python3
"""Cheap DEX-to-release class-set candidate scoring.

This is a narrowing primitive only. It compares class identities exposed by a
target DEX/APK with class identities in candidate JAR/AAR/APK/ZIP artifacts.
It does not establish component identity, version identity, or modification
state. Structural FID/other evidence is still required before attribution.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import struct
import zipfile

MAX_CLASSES = 500_000
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 200_000


def sha256_path(path: pathlib.Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def uleb128(data: bytes, off: int) -> tuple[int,int]:
    value=0
    shift=0
    for i in range(5):
        if off+i >= len(data):
            raise ValueError("truncated uleb128")
        b=data[off+i]
        value |= (b & 0x7f) << shift
        if not (b & 0x80):
            return value, off+i+1
        shift += 7
    raise ValueError("uleb128 too long")


def dex_classes(data: bytes) -> set[str]:
    if len(data) < 112 or not data.startswith(b"dex\n"):
        raise ValueError("not a DEX")
    string_count,string_off=struct.unpack_from("<II",data,56)
    type_count,type_off=struct.unpack_from("<II",data,64)
    class_count,class_off=struct.unpack_from("<II",data,96)
    if max(string_count,type_count,class_count) > MAX_CLASSES:
        raise ValueError("DEX table count exceeds bound")
    if string_off+4*string_count > len(data) or type_off+4*type_count > len(data) or class_off+32*class_count > len(data):
        raise ValueError("DEX table outside file")
    string_offsets=[struct.unpack_from("<I",data,string_off+4*i)[0] for i in range(string_count)]
    type_string=[struct.unpack_from("<I",data,type_off+4*i)[0] for i in range(type_count)]
    out=set()
    for i in range(class_count):
        class_idx=struct.unpack_from("<I",data,class_off+32*i)[0]
        if class_idx >= len(type_string):
            continue
        sidx=type_string[class_idx]
        if sidx >= len(string_offsets):
            continue
        off=string_offsets[sidx]
        _,pos=uleb128(data,off)
        end=data.find(b"\x00",pos)
        if end < 0:
            continue
        desc=data[pos:end].decode("utf-8","replace")
        if desc.startswith("L") and desc.endswith(";"):
            out.add(desc)
    return out


def class_from_path(name: str) -> str | None:
    if not name.endswith(".class"):
        return None
    if name.startswith("META-INF/") or name.endswith("/module-info.class") or name == "module-info.class":
        return None
    body=name[:-6]
    if body.endswith("package-info"):
        return None
    return "L"+body+";"


def classes_from_zip_bytes(blob: bytes, *, allow_nested_classes_jar: bool=True) -> set[str]:
    out=set()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        infos=[x for x in z.infolist() if not x.is_dir()]
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("archive entry count exceeds bound")
        for info in infos:
            if info.file_size > MAX_ENTRY_BYTES:
                continue
            cls=class_from_path(info.filename)
            if cls:
                out.add(cls)
                continue
            base=pathlib.PurePosixPath(info.filename).name
            if base.startswith("classes") and base.endswith(".dex"):
                out.update(dex_classes(z.read(info)))
                continue
            if allow_nested_classes_jar and base == "classes.jar":
                out.update(classes_from_zip_bytes(z.read(info),allow_nested_classes_jar=False))
    return out


def classes_from_artifact(path: pathlib.Path) -> set[str]:
    data=path.read_bytes()
    if data.startswith(b"dex\n"):
        return dex_classes(data)
    if zipfile.is_zipfile(path):
        return classes_from_zip_bytes(data)
    raise ValueError(f"unsupported target/reference container: {path}")


def simple_name(desc: str) -> str:
    body=desc[1:-1] if desc.startswith("L") and desc.endswith(";") else desc
    return body.rsplit("/",1)[-1]


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--candidate",action="append",default=[],help="LABEL=PATH; repeat for bounded candidates")
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    if not a.candidate:
        raise SystemExit("at least one --candidate LABEL=PATH is required")

    target=pathlib.Path(a.target).resolve()
    target_classes=classes_from_artifact(target)
    if not target_classes:
        raise SystemExit("target exposes no classes")

    target_simple={simple_name(x) for x in target_classes}
    results=[]
    seen_labels=set()
    for spec in a.candidate:
        if "=" not in spec:
            raise SystemExit(f"candidate must be LABEL=PATH: {spec}")
        label,raw=spec.split("=",1)
        label=label.strip()
        if not label or label in seen_labels:
            raise SystemExit(f"invalid/duplicate candidate label: {label!r}")
        seen_labels.add(label)
        path=pathlib.Path(raw).resolve()
        refs=classes_from_artifact(path)
        exact=target_classes & refs
        ref_simple={simple_name(x) for x in refs}
        simple=target_simple & ref_simple
        results.append({
            "label":label,
            "path":str(path),
            "sha256":sha256_path(path),
            "reference_class_count":len(refs),
            "exact_class_overlap_count":len(exact),
            "target_exact_coverage":len(exact)/len(target_classes),
            "reference_exact_coverage":len(exact)/len(refs) if refs else 0.0,
            "simple_name_overlap_count":len(simple),
            "simple_name_overlap_is_identity_evidence":False,
            "exact_overlap_sample":sorted(exact)[:200],
        })

    doc={
        "schema":"aar-dex-classset-candidate-score/v0",
        "target":{
            "path":str(target),
            "sha256":sha256_path(target),
            "class_count":len(target_classes),
        },
        "candidates":results,
        "policy":{
            "purpose":"candidate-narrowing-before-structural-correspondence",
            "component_identity_claims":False,
            "version_identity_claims":False,
            "modification_state_claims":False,
            "simple_name_overlap_is_family_hint_only":True,
            "structural_fid_or_stronger_evidence_required_for_attribution":True,
        },
    }
    out=pathlib.Path(a.out)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(doc,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"target_classes":len(target_classes),"candidate_count":len(results)},indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
