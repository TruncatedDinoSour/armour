#include "error.h"

#include <string.h>

const char *pDBv1Error_to_string(pDBv1Error error) {
    switch (error) {
        case pDBv1Error_SUCCESS: return "success";
        case pDBv1Error_READ: return "read error";
        case pDBv1Error_UNSUPPORTED_VERSION: return "unsupported pDB version";
        case pDBv1Error_INPUT: return "invalid input arguments";
        case pDBv1Error_MEMORY: return "memory error";
        case pDBv1Error_INIT: return "initialization error";
        case pDBv1Error_FORMAT: return "database format error";
        case pDBv1Error_LOCKED: return "database is locked";
        case pDBv1Error_INTEGRITY: return "integrity checks failed";
        case pDBv1Error_VALUE: return "invalid value(s)";
        case pDBv1Error_INSECURE: return "insecure value(s)";
    }

    return NULL;
}
