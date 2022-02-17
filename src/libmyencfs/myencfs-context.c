#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-static.h>
#include <myencfs/myencfs-context.h>

#include "myencfs-error-internal.h"

struct __myencfs_context_s {
	myencfs_system system;
	void *user_context;
};

myencfs_context
myencfs_context_new(
	const myencfs_system system
) {
	myencfs_context context = NULL;
	myencfs_context ret = NULL;

	myencfs_static_init(system);

	if ((context = myencfs_system_zalloc(system, "myencfs_context", sizeof(*context))) == NULL) {
		goto cleanup;
	}

	context->system = system;

	ret = context;
	context = NULL;

cleanup:

	myencfs_context_destruct(context);

	return ret;
}

bool
myencfs_context_construct(
	const myencfs_context context __attribute__((unused))
) {
	return true;
}

bool
myencfs_context_destruct(
	const myencfs_context context
) {
	bool ret = true;

	if (context != NULL) {
		if (!myencfs_system_free(context->system, "myencfs_context", context)) {
			ret = false;
		}
	}

	return ret;
}

myencfs_system
myencfs_context_get_system(
	const myencfs_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return context->system;
}

const void *
myencfs_context_get_user_context(
	const myencfs_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return context->user_context;
}

bool
myencfs_context_set_user_context(
	const myencfs_context context,
	void *user_context
) {
	if (context == NULL) {
		return false;
	}
	context->user_context = user_context;
	return true;
}

myencfs_error
myencfs_context_get_error(
	const myencfs_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return myencfs_system_get_error(context->system);
}

void
myencfs_context_error_reset(
	const myencfs_context context
) {
	myencfs_error_reset(myencfs_context_get_error(context));
}
