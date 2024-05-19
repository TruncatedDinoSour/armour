#include "argon2.h"

uint8_t Argon2_exists(const uint8_t argon2_type) {
    switch (argon2_type) {
        case Argon2Type_D:
        case Argon2Type_I:
        case Argon2Type_ID: return 1;

        default: return 0;
    }
}
