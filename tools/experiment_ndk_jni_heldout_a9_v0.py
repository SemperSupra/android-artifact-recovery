#!/usr/bin/env python3
"""A9 producer-only PREREGISTERED source-known unsigned modular arithmetic holdout.

The A9 source fixture and constants were committed before native Ghidra
qualification. This file must not be imported by the source-blind actor.
"""
CPP_HELDOUT_A9 = r'''
#include <jni.h>
#include <stdint.h>
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_fold(uint32_t x) {
    return ((x + 0x6d2b79f5u) * 0x9e3779b1u) ^ 0xa5f1523du;
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
