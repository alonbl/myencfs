#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#include "myencfs-util.h"

const char *
_myencfs_util_snprintf(
	char * const buf,
	size_t size,
	const char * const format,
	...
) {
	va_list ap;

	va_start(ap, format);
	vsnprintf(buf, size, format, ap);
	va_end(ap);

	return buf;
}
