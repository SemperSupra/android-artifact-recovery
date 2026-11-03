#!/usr/bin/env python3
"""A7 producer-only source-known typed JNI fixture for x86_64/aarch64 Ghidra.

This source is for the ELF producer and the independent owner oracle only.
Do not import it from the decompiler, A4 reconstructor, or model/actor.
Compiler-specific negative signed right shifts are never treated as a
cross-ABI semantic oracle. The goal is Ghidra type evidence + safe abstention.
"""
CPP_TYPED = r'''
#include <jni.h>
#include <stdint.h>
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_fold(uint32_t x) {
    return (x >> 1) ^ 0x13579bdfu;
}
__attribute__((noinline,visibility("hidden")))
static int32_t aar_affine(int32_t x) {
    return (x >> 1) ^ 0x02468ace;
}
extern "C" JNIEXPORT jint JNICALL
Java_org_sempersupra_aar_golden_NativeBridge_nativeDispatch(
    JNIEnv*, jclass, jint mode, jint value) {
    if (mode == 5) return (jint)aar_fold((uint32_t)value);
    if (mode == 7) return (jint)aar_affine((int32_t)value);
    return (jint)-1;
}
'''
