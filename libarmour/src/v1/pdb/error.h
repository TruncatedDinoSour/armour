#ifndef _PDBv1_ERROR_H
#define _PDBv1_ERROR_H

typedef enum pDBv1Error {
    pDBv1Error_SUCCESS = 0,
    pDBv1Error_READ,
    pDBv1Error_UNSUPPORTED_VERSION,
    pDBv1Error_INPUT,
    pDBv1Error_MEMORY,
    pDBv1Error_INIT,
    pDBv1Error_FORMAT,
    pDBv1Error_LOCKED,
    pDBv1Error_INTEGRITY,
    pDBv1Error_VALUE,
    pDBv1Error_INSECURE
} pDBv1Error;

const char *pDBv1Error_to_string(pDBv1Error error);
#endif /* _PDBv1_ERROR_H */
