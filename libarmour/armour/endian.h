#ifndef _ARMOUR_ENDIAN_H
#define _ARMOUR_ENDIAN_H

#include <stdint.h>

uint8_t *u16_to_le_bytes(const uint16_t value, uint8_t bytes[2]);
uint8_t *u32_to_le_bytes(const uint32_t value, uint8_t bytes[4]);

/*
 * endian.h isn't a part of the C89 standard, so we cannot use it.
 * We use byte wrapping, because we are reading raw bytes from storage (pDB
 * database), and if it's big endian we need to wrap it.
 */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_host_u16(le_value) (uint16_t)((le_value >> 8) | (le_value << 8))
#define to_host_u32(le_value)                                             \
    (uint32_t)(((le_value >> 24) & 0xff) | ((le_value << 8) & 0xff0000) | \
               ((le_value >> 8) & 0xff00) | ((le_value << 24) & 0xff000000))
#else
#define to_host_u16(le_value) (uint16_t)(le_value)
#define to_host_u32(le_value) (uint32_t)(le_value)
#endif

/*
 * Convert bits to bytes.
 */
#define b2B(bits) ((bits) / 8)

#endif /* _ARMOUR_ENDIAN_H */
