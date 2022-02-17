#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <myencfs/myencfs-system-driver-myencfs.h>
#include <myencfs/myencfs-system.h>

#include "myencfs-error-internal.h"
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

bool
_myencfs_util_createdir(
	const myencfs_system system,
	const char * const base,
	const char * const name
) {
	char *work = NULL;
	char *p;
	char *t;
	bool ret = false;

	if ((work = myencfs_system_strdup(system, "createdir::work", name)) == NULL) {
		goto cleanup;
	}

	p = work + strlen(base);

	/* WSL2 supports both '/' and '\\' */
	for (t = p + strlen(p); t > p && *t != '/' && *t != _MYENCFS_PATH_SEPARTOR; t--);
	*t = '\0';

	if (*p == '\0') {
		ret = true;
		goto cleanup;
	}

	while(true) {
		/* WSL2 supports both '/' and '\\' */
		if (*p == '\0' || *p == '/' || *p == _MYENCFS_PATH_SEPARTOR) {
			char c = *p;
			*p = '\0';

			if (!myencfs_system_driver_myencfs_access(system)(system, work, F_OK)) {
				if (!myencfs_system_driver_myencfs_mkdir(system)(system, work, 0770)) {
					_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_system_get_error(system)),
						"createdir",
						MYENCFS_ERROR_CODE_IO,
						true,
						"Failed to create directory '%s'",
						work
					));
					goto cleanup;
				}
			}

			*p = c;
		}
		if (*p == '\0') {
			ret = true;
			goto cleanup;
		}
		p++;
	}

	ret = true;

cleanup:

	myencfs_system_free(system, "createdir::work", work);

	return ret;
}
