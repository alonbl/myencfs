#ifndef __MYENCFS_UTIL_H
#define __MYENCFS_UTIL_H

#include <stdlib.h>

#define _MYENCFS_UTIL_MIN(x, y) ((x) < (y) ? (x) : (y))
#define _MYENCFS_UTIL_MAX(x, y) ((x) > (y) ? (x) : (y))

const char *
_myencfs_util_snprintf(
	char * const buf,
	size_t size,
	const char * const format,
	...
) __attribute__((format(printf, 3, 4)));

bool
_myencfs_util_createdir(
	const myencfs_system system,
	const char * const base,
	const char * const name
);

#endif
