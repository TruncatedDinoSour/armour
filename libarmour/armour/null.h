#ifndef _ARMOUR_NULL_H
#define _ARMOUR_NULL_H

#include <unistd.h> /* Maybe provides NULL. */

/*
 * Just in case NULL isn't available. (C89 standard)
 */

#ifndef NULL
#define NULL ((void *)0)
#endif /* NULL */

#endif /* _ARMOUR_NULL_H */
