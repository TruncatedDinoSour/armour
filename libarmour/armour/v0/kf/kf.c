#include "kf.h"

#include <fcntl.h>
#include <unistd.h>

int Kfv0_open(const char *filename) { return open(filename, O_RDWR); }

int Kfv0_close(const int fd) { return close(fd); }
