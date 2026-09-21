#include "known_component.h"

uint64_t aar_known_mix(uint64_t value) {
    return (value << 7) | (value >> (64 - 7));
}

uint32_t aar_known_checksum(const uint8_t *data, size_t size) {
    uint32_t acc = 0;
    for (size_t i = 0; i < size; ++i) {
        acc += (uint32_t)data[i] * (uint32_t)(i + 1);
    }
    return acc;
}
