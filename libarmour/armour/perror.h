#ifndef _ARMOUR_pERROR_H
#define _ARMOUR_pERROR_H

typedef enum pError {
    pError_SUCCESS = 0,
    pError_READ,
    pError_UNSUPPORTED_VERSION,
    pError_INPUT,
    pError_MEMORY,
    pError_FORMAT,
    pError_LOCKED,
    pError_INTEGRITY,
    pError_VALUE,
    pError_INSECURE,
    pError_INIT
} pError;

const char *pError_to_string(const pError error);
#endif /* _ARMOUR_pERROR_H */
