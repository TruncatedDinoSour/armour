#include "pdb.h"

#include <fcntl.h>
#include <unistd.h>

int pDBv1_open(const char *filename) { return open(filename, O_RDWR); }

int pDBv1_close(const int fd) { return close(fd); }
