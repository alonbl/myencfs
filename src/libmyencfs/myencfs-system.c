#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "myencfs-error-internal.h"
#include "myencfs-system-driver-core.h"
#include "myencfs-util.h"

struct myencfs_system_s {
	const void *userdata;
	struct myencfs_system_driver_entry_s driver_entries[256];
	myencfs_error error;
};

static
myencfs_error_entry
__error_entry_errno(
	const myencfs_error_entry entry
) {
	char msg[1024];
	int old_errno;

	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_ERRNO, errno);

	old_errno = errno;
	errno = 0;
	msg[0] = '\0';
	strerror_r(old_errno, msg, sizeof(msg));
	if (errno == 0) {
		_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_ERRNO_STR, msg);
	}
	errno = old_errno;

	return entry;
}

#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT

static
void
__driver_default_explicit_bzero(
	const myencfs_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
#if defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(p, size);
#elif defined(HAVE_SECUREZEROMEMORY)
	SecureZeroMemory(p, size);
#else
	memset(p, 0, size);
#endif
}

static
void *
__driver_default_realloc(
	const myencfs_system system,
	const char * const hint,
	void * const p,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		return NULL;
	}

	if ((ret =  realloc(p, size)) == NULL) {
		_myencfs_error_entry_dispatch(
			_myencfs_error_entry_prm_add_u64(
				_myencfs_error_entry_base(
					_myencfs_error_capture(system->error),
					hint,
					MYENCFS_ERROR_CODE_MEMORY,
					true,
					"Memory allocation failed"
				),
				MYENCFS_ERROR_KEY_RESOURCE_SIZE,
				size
			)
		);
	}

	return ret;
}

static
bool
__driver_default_free(
	const myencfs_system system __attribute__((unused)),
	const char * const hint __attribute__((unused)),
	void * const p
) {
	free(p);
	return true;
}

static
bool
__driver_default_mkdir(
	const myencfs_system system __attribute__((unused)),
	const char * const path,
	const mode_t mode
) {
	char buf[1024];
	bool ret = false;
	int r;

#ifdef _WIN32
	(void)mode;
	r = mkdir(path);
#else
	r = mkdir(path, mode);
#endif
	if (r == -1) {
		_myencfs_error_entry_dispatch(
			_myencfs_error_entry_prm_add_str(
				_myencfs_error_entry_base(
					__error_entry_errno(_myencfs_error_capture(system->error)),
					_myencfs_util_snprintf(buf, sizeof(buf), "mkdir::%s", path),
					MYENCFS_ERROR_CODE_IO,
					true,
					"Directory '%s' creation failed",
					path
				),
				MYENCFS_ERROR_KEY_RESOURCE_NAME,
				path
			)
		);
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

static
bool
__driver_default_access(
	const myencfs_system system __attribute__((unused)),
	const char * const path,
	const int mode
) {
	return access(path, mode) != -1;
}

#pragma GCC diagnostic ignored "-Wcast-function-type"
static const struct myencfs_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ MYENCFS_SYSTEM_DRIVER_ID_core_explicit_bzero, (void (*)()) __driver_default_explicit_bzero},
	{ MYENCFS_SYSTEM_DRIVER_ID_core_free, (void (*)()) __driver_default_free},
	{ MYENCFS_SYSTEM_DRIVER_ID_core_realloc, (void (*)()) __driver_default_realloc},
	{ MYENCFS_SYSTEM_DRIVER_ID_core_mkdir, (void (*)()) __driver_default_mkdir},
	{ MYENCFS_SYSTEM_DRIVER_ID_core_access, (void (*)()) __driver_default_access},

	{ 0, NULL}
};
#pragma GCC diagnostic pop
#else
static const struct myencfs_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ 0, NULL}
};
#endif

size_t
myencfs_system_get_context_size(void) {
	return sizeof(*(myencfs_system)NULL);
}

myencfs_system
myencfs_system_new() {
#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT
	myencfs_system system = NULL;
	myencfs_system ret = NULL;

	if ((system = realloc(NULL, sizeof(*system))) == NULL) {
		goto cleanup;
	}

	memset(system, 0, sizeof(*system));

	if (!myencfs_system_init(system, sizeof(*system))) {
		goto cleanup;
	}

	ret = system;
	system = NULL;

cleanup:

	free(system);

	return ret;
#else
	return NULL;
#endif
}

bool
myencfs_system_init(
	const myencfs_system system,
	const size_t size
) {
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	if (MYENCFS_SYSTEM_CONTEXT_SIZE < myencfs_system_get_context_size()) {
		goto cleanup;
	}

	if (size < myencfs_system_get_context_size()) {
		goto cleanup;
	}

	myencfs_system_clean(system, size);

	myencfs_system_driver_register(system, __DRIVER_ENTRIES);

	ret = true;

cleanup:

	return ret;
}

bool
myencfs_system_construct(
	const myencfs_system system
) {
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	if ((system->error = _myencfs_error_new(system)) == NULL) {
		goto cleanup;
	}

	if (!_myencfs_error_construct(system->error)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
myencfs_system_destruct(
	const myencfs_system system __attribute__((unused))
) {
	bool ret = true;
#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT
	ret = myencfs_system_clean(system, sizeof(*system));
	free(system);
#endif
	return ret;
}

bool
myencfs_system_clean(
	const myencfs_system system,
	const size_t size
) {
	bool ret = false;

	if (size < myencfs_system_get_context_size()) {
		goto cleanup;
	}

	if (system != NULL) {
		_myencfs_error_destruct(system->error);
		memset(system, 0, sizeof(*system));
	}

	ret = true;

cleanup:

	return ret;
}

bool
myencfs_system_driver_register(
	const myencfs_system system,
	const struct myencfs_system_driver_entry_s * const entries
) {
	struct myencfs_system_driver_entry_s *t;
	const struct myencfs_system_driver_entry_s *s;
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	for (t = system->driver_entries; t->id != 0; t++);
	for (s = entries; s->id != 0; s++);
	s++;

	if (s - entries >= system->driver_entries + sizeof(system->driver_entries) / sizeof(*system->driver_entries) - t) {
		goto cleanup;
	}

	memcpy(t, entries, sizeof(*entries) * (s - entries));

	ret = true;

cleanup:

	return ret;
}

void (*myencfs_system_driver_find(
	const myencfs_system system,
	const unsigned id
))() {
	struct myencfs_system_driver_entry_s *x;
	void (*ret)() = NULL;

	if (system == NULL) {
		return NULL;
	}

	/* TODO: optimize */
	for (x = system->driver_entries; x->id != 0; x++) {
		if (x->id == id) {
			ret = x->f;
		}
	}

	return ret;
}

const void *
myencfs_system_get_userdata(
	const myencfs_system system
) {
	if (system == NULL) {
		return NULL;
	}

	return system->userdata;
}

bool
myencfs_system_set_userdata(
	const myencfs_system system,
	const void *userdata
) {
	if (system == NULL) {
		return false;
	}

	system->userdata = userdata;
	return true;
}

myencfs_error
myencfs_system_get_error(
	const myencfs_system system
) {
	if (system == NULL) {
		return NULL;
	}

	return system->error;
}

void
myencfs_system_explicit_bzero(
	const myencfs_system system,
	void * const p,
	const size_t size
) {
	myencfs_system_driver_core_explicit_bzero(system)(system, p, size);
}

void *
myencfs_system_realloc(
	const myencfs_system system,
	const char * const hint,
	void * const p,
	const size_t size
) {
	return myencfs_system_driver_core_realloc(system)(system, hint, p, size);
}

bool
myencfs_system_free(
	const myencfs_system system,
	const char * const hint,
	void * const p
) {
	return myencfs_system_driver_core_free(system)(system, hint, p);
}

void *
myencfs_system_zalloc(
	const myencfs_system system,
	const char * const hint,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		return NULL;
	}

	if ((ret = myencfs_system_realloc(system, hint, NULL, size)) == NULL) {
		goto cleanup;
	}

	myencfs_system_explicit_bzero(system, ret, size);

cleanup:

	return ret;
}

char *
myencfs_system_strdup(
	const myencfs_system system,
	const char * const hint,
	const char * const s
) {
	char *ret = NULL;
	size_t size;

	if (system == NULL) {
		return NULL;
	}

	if (s == NULL) {
		goto cleanup;
	}

	size = strlen(s) + 1;

	if ((ret = myencfs_system_realloc(system, hint, NULL, size)) == NULL) {
		goto cleanup;
	}

	memcpy(ret, s, size);

cleanup:

	return ret;
}
