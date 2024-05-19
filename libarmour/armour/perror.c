#include "perror.h"

#include "null.h"

#include <unistd.h>

const char *pError_to_string(const pError error) {
    switch (error) {
        case pError_SUCCESS: return "success";
        case pError_READ: return "read error";
        case pError_UNSUPPORTED_VERSION: return "unsupported pDB version";
        case pError_INPUT: return "invalid input arguments";
        case pError_MEMORY: return "memory error";
        case pError_FORMAT: return "database format error";
        case pError_LOCKED: return "database is locked";
        case pError_INTEGRITY: return "integrity checks failed";
        case pError_VALUE: return "invalid value(s)";
        case pError_INSECURE: return "insecure value(s)";
        case pError_INIT: return "initialization error";
    }

    return NULL;
}
