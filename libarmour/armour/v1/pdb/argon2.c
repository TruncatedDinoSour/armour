#include "argon2.h"

uint8_t pDBv1_argon2_exists(uint8_t argon2_type) {
    switch (argon2_type) {
        case pDBv1Argon2Type_D:
        case pDBv1Argon2Type_I:
        case pDBv1Argon2Type_ID: return 1;

        default: return 0;
    }
}
