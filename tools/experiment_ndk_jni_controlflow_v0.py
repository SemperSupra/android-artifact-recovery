#!/usr/bin/env python3
"""A-6 independent, source-authored branching/looping JNI golden.

Disjoint in operator structure from the A-2/A-5 single-expression arithmetic
goldens. This module is PRODUCER-ONLY and never imported by the Ghidra script or
the source-blind candidate. The oracle is separately implemented.
"""
CPP_CONTROL_FLOW = r'''
#include <jni.h>
#include <stdint.h>
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_fold(uint32_t x) {
    uint32_t y = x ^ 0xa5a55a5au;
    if ((x & 1u) != 0u)
        y = y * 33u + 0x13579bdfu;
    else
        y = (y >> 5) ^ (y << 27) ^ 0x2468ace0u;
    return y;
}
__attribute__((noinline,visibility("hidden")))
static uint32_t aar_affine(uint32_t x) {
    uint32_t y = x ^ 0x10203040u;
    for (unsigned int i = 0; i < 4u; ++i)
        y = (y ^ (y >> 13)) * 0x27d4eb2du + (i + 1u);
    return y;
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
