#include "endian.h"

#include <stdint.h>

/*
 * Convert integers to little-endian bytes.
 */

uint8_t *u16_to_le_bytes(const uint16_t value, uint8_t bytes[2]) {
    bytes[0] = (uint8_t)(value);
    bytes[1] = (uint8_t)(value >> 8);
    return bytes;
}

uint8_t *u32_to_le_bytes(const uint32_t value, uint8_t bytes[4]) {
    bytes[0] = (uint8_t)(value);
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
    return bytes;
}
