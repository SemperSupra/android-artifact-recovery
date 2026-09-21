#pragma once
#include <stddef.h>
#include <stdint.h>

uint64_t aar_known_mix(uint64_t value);
uint32_t aar_known_checksum(const uint8_t *data, size_t size);
