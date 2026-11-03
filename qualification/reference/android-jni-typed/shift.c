#include <stdint.h>
uint32_t f_uu(uint32_t a) { return a >> 1; }
int32_t f_ii(int32_t a) { return a >> 1; }
uint32_t f_ui(int32_t a) { return (uint32_t)(a >> 1); }
int32_t f_iu(uint32_t a) { return (int32_t)(a >> 1); }
