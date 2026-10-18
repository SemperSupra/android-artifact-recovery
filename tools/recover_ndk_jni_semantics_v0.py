#!/usr/bin/env python3
"""A-4 source-blind Ghidra pseudocode -> restricted 32-bit expression IR.

This module deliberately does not import CPP, expected(), JNI symbols, source
maps or any source-side address oracle. No eval/exec or general C interpreter.
Grammar is intentionally tiny; unsupported decompilation must FAIL/UNKNOWN.
"""
from __future__ import annotations
import argparse,ast,base64,hashlib,json,re,sys
from pathlib import Path

OPS={ast.Add:"add",ast.Mult:"mul",ast.BitXor:"xor",ast.BitOr:"or",
     ast.BitAnd:"and",ast.LShift:"shl",ast.RShift:"shr"}
MAP={v:k for k,v in OPS.items()}
def convert(node,depth=0):
    if depth>28:raise ValueError("A4 expression depth exceeded")
    if isinstance(node,ast.Name) and node.id=="param_1":return {"input":"param_1"}
    if isinstance(node,ast.Constant) and type(node.value)==int and 0<=node.value<=0xffffffff:
        return {"constant":node.value}
    if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.USub):
        return {"neg":convert(node.operand,depth+1)}
    if isinstance(node,ast.BinOp) and type(node.op) in OPS:
        return {"op":OPS[type(node.op)],"args":[convert(node.left,depth+1),convert(node.right,depth+1)]}
    raise ValueError("unsupported decompiled C operation (fail closed)")
def evaluate(tree,u,depth=0):
    if depth>28:raise ValueError("deep IR")
    if type(tree)!=dict:raise ValueError("wrong IR node")
    if set(tree)=={"input"} and tree["input"]=="param_1":return u&0xffffffff
    if set(tree)=={"constant"} and type(tree["constant"])==int and 0<=tree["constant"]<=0xffffffff:
        return tree["constant"]
    if set(tree)=={"neg"}:return (-evaluate(tree["neg"],u,depth+1))&0xffffffff
    if set(tree)=={"op","args"} and tree["op"] in MAP and type(tree["args"])==list and len(tree["args"])==2:
        a,b=(evaluate(z,u,depth+1) for z in tree["args"])
        k=tree["op"]
        if k=="add":v=a+b
        elif k=="mul":v=a*b
        elif k=="xor":v=a^b
        elif k=="or":v=a|b
        elif k=="and":v=a&b
        elif k=="shl":v=a<<b if b<=31 else 0
        else:v=a>>b if b<=31 else 0
        return v&0xffffffff
    raise ValueError("unrecognized or forged semantic IR")
def parse_c(value):
    if not 12<len(value)<4096 or "aar_fold" in value or "aar_affine" in value:
        raise ValueError("Ghidra pseudocode size/hidden-symbol leak")
    m=re.fullmatch(r"\s*(?:uint|int)\s+FUN_[0-9A-Fa-f]+\s*\(\s*(?:uint|int)\s+param_1\s*\)\s*\{\s*return\s+([^;{}]+);\s*\}\s*",value)
    if not m:raise ValueError("unhandled pseudocode structure")
    expr=m.group(1)
    if len(expr)>1200:raise ValueError("expression too large")
    tree=convert(ast.parse(expr,mode="eval").body)
    return tree
def one(log,tag):
    vals=re.findall(r"AAR_A4_"+tag+r"=([^\s]+)",log)
    if len(vals)!=1:raise ValueError("missing/duplicate Ghidra evidence "+tag)
    return vals[0]
def recover(log,abi):
    if abi not in ("x86_64","aarch64") or one(log,"ABI")!=abi:raise ValueError("ABI mismatch")
    base=int(one(log,"BASE"),16)
    lines=re.findall(r"AAR_A4_IR=([a-f0-9]+)\|([A-Za-z0-9+/=]+)",log)
    if len(lines)!=2 or int(one(log,"COUNT"))!=2:raise ValueError("two native functions required")
    out={}
    for address,encoded in lines:
        rva=int(address,16)-base
        if rva<=0 or rva in out:raise ValueError("invalid/repeated callee entry")
        raw=base64.b64decode(encoded,validate=True)
        if len(raw)>4096:raise ValueError("oversized decompiler output")
        out[rva]={"expression":parse_c(raw.decode("ascii")),
                  "ghidra_decomp_sha256":hashlib.sha256(raw).hexdigest()}
    return {"schema":1,"abi":abi,
            "source_blind":True,"source_map_available_to_reconstructor":False,
            "helpers":{format(a,"x"):v for a,v in sorted(out.items())},
            "actor_qualified":False}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--abi",choices=("x86_64","aarch64"),required=True)
    p.add_argument("--log",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    if a.log.stat().st_size>5_000_000:raise ValueError("oversized log")
    ir=recover(a.log.read_text(errors="replace"),a.abi)
    a.out.write_text(json.dumps(ir,sort_keys=True,indent=2)+"\n")
    print("A4_RECOVERED="+json.dumps({"abi":a.abi,"helper_count":len(ir["helpers"]),
        "candidate_sha256":hashlib.sha256(a.out.read_bytes()).hexdigest(),
        "source_blind_reconstruction":True,"oracle_comparison_performed":False},sort_keys=True))
if __name__=="__main__":
    try:main()
    except (OSError,ValueError,SyntaxError,UnicodeError) as e:
        print("A4_RECOVERY_FAIL="+str(e),file=sys.stderr)
        raise SystemExit(1)
