#include <stdint.h>
/* Independently compiled source-known reference, never imported by A8 actor. */
uint32_t a8_u32_reference(uint32_t value) {
    return (value >> 1) ^ UINT32_C(0x13579bdf);
}
