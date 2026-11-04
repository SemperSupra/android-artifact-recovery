#include <stdint.h>
/* A9 independent source-known reference uses wider intermediates and explicit
 * uint32 modular truncation rather than the producer's same C expression. */
uint32_t a9_u32_reference(uint32_t x) {
    uint64_t sum = (uint64_t)x + UINT64_C(0x6d2b79f5);
    uint64_t product = (sum & UINT64_C(0xffffffff)) * UINT64_C(0x9e3779b1);
    return (uint32_t)((product & UINT64_C(0xffffffff)) ^ UINT64_C(0xa5f1523d));
}
