#ifndef _ARMOUR_ARGON2_H
#define _ARMOUR_ARGON2_H

#include <stdint.h>

typedef enum Argon2Type {
    Argon2Type_D  = 0x00,
    Argon2Type_I  = 0x01,
    Argon2Type_ID = 0x02
} Argon2Type;

uint8_t Argon2_exists(const uint8_t argon2_type);

#endif /* _ARMOUR_ARGON2_H */
