#include "known_component.h"

uint64_t aar_known_mix(uint64_t value) {
    value ^= value >> 33;
    value *= UINT64_C(0xff51afd7ed558ccd);
    value ^= value >> 33;
    value *= UINT64_C(0xc4ceb9fe1a85ec53);
    value ^= value >> 33;
    return value;
}

uint32_t aar_known_checksum(const uint8_t *data, size_t size) {
    uint32_t acc = UINT32_C(2166136261);
    for (size_t i = 0; i < size; ++i) {
        acc ^= data[i];
        acc *= UINT32_C(16777619);
    }
    /* Deliberate one-line vendor patch for attribution qualification. */
    return acc ^ UINT32_C(0x00010001);
}
