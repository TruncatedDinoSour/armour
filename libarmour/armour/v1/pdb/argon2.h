#ifndef _PDBv1_ARGON2_H
#define _PDBv1_ARGON2_H

#include <stdint.h>

typedef enum pDBv1Argon2Type {
    pDBv1Argon2Type_D  = 0x00,
    pDBv1Argon2Type_I  = 0x01,
    pDBv1Argon2Type_ID = 0x02
} pDBv1Argon2Type;

uint8_t pDBv1_argon2_exists(uint8_t argon2_type);

#endif /* _PDBv1_ARGON2_H */
