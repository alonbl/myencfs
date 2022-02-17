#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myencfs/myencfs-static.h>

#include "myencfs-error-internal.h"

int main() {

	char buf[1024 * 10];
	char _myencfs_system[MYENCFS_SYSTEM_CONTEXT_SIZE] = {0};
	myencfs_system system = (myencfs_system)_myencfs_system;
	myencfs_error error = NULL;
	char buffer[1024];
	uint32_t code;
	int ret = 1;

	memset(_myencfs_system, 0, sizeof(_myencfs_system));

	if (!myencfs_system_init(system, sizeof(_myencfs_system))) {
		goto cleanup;
	}

	if (!myencfs_system_construct(system)) {
		goto cleanup;
	}

	if (!myencfs_static_init(system)) {
		goto cleanup;
	}

	error = myencfs_system_get_error(system);

	if (myencfs_error_format_simple(error, &code, buffer, sizeof(buffer))) {
		printf("Expecting success\n");
		goto cleanup;
	}
	if (code != MYENCFS_ERROR_CODE_SUCCESS) {
		printf("Expecting success\n");
		goto cleanup;
	}

	_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
		_myencfs_error_capture(error),
		"hint1",
		1111,
		false,
		"hello %d",
		1
	));

	_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
		_myencfs_error_capture(error),
		"hint2",
		2222,
		false,
		"hello %d",
		2
	));

	if (!myencfs_error_format_simple(error, &code, NULL, 0)) {
		printf("Expecting failure\n");
		goto cleanup;
	}
	if (code != 1111) {
		printf("Expecting 1111\n");
		goto cleanup;
	}

	if (!myencfs_error_format_simple(error, &code, buffer, sizeof(buffer))) {
		printf("Expecting failure\n");
		goto cleanup;
	}
	if (code != 1111) {
		printf("Expecting 1111\n");
		goto cleanup;
	}
	if (strcmp(buffer, "hello 1")) {
		printf("Expecting correct message\n");
		goto cleanup;
	}

	_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
		_myencfs_error_capture(error),
		"hint3",
		3333,
		true,
		"hello %d",
		3
	));

	_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
		_myencfs_error_capture(error),
		"hint3",
		4444,
		false,
		"hello %d",
		4
	));

	if (!myencfs_error_format_simple(error, &code, buffer, sizeof(buffer))) {
		printf("Expecting failure\n");
		goto cleanup;
	}
	if (code != 3333) {
		printf("Expecting 3333\n");
		goto cleanup;
	}

	myencfs_error_format(error, buf, sizeof(buf));
	puts(buf);

	myencfs_error_reset(error);

	if (myencfs_error_format_simple(error, &code, buffer, sizeof(buffer))) {
		printf("Expecting success cleanup\n");
		goto cleanup;
	}
	if (code != MYENCFS_ERROR_CODE_SUCCESS) {
		printf("Expecting success cleanup\n");
		goto cleanup;
	}

	ret = 0;

cleanup:

	myencfs_static_clean(system);
	myencfs_system_clean(system, sizeof(_myencfs_system));

	return ret;
}
