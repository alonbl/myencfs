#ifndef __MYENCFS_SYSTEM_H
#define __MYENCFS_SYSTEM_H

#include <stdbool.h>
#include <stdlib.h>

#include "myencfs-error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __MYENCFS_SYSTEM_DRIVER_FUNC_COMMON(group, name) \
	static inline myencfs_system_driver_p_##group##_##name myencfs_system_driver_##group##_##name (const myencfs_system system) { \
		return (myencfs_system_driver_p_##group##_##name)myencfs_system_driver_find(system, MYENCFS_SYSTEM_DRIVER_ID_##group##_##name); \
	}
#if defined(HAVE_C99_VARARGS_MACROS)
#define MYENCFS_SYSTEM_DRIVER_FUNC(group, ret, name, ...) \
	typedef ret (*myencfs_system_driver_p_##group##_##name)(const myencfs_system system __VA_OPT__(,) __VA_ARGS__); \
	__MYENCFS_SYSTEM_DRIVER_FUNC_COMMON(group, name)
#elif defined(HAVE_GCC_VARARGS_MACROS)
#define MYENCFS_SYSTEM_DRIVER_FUNC(group, ret, name, ...) \
	typedef ret (*myencfs_system_driver_p_##group##_##name)(const myencfs_system system, ##__VA_ARGS__); \
	__MYENCFS_SYSTEM_DRIVER_FUNC_COMMON(group, name)
#else
#error no available varargs macros method
#endif

#define MYENCFS_SYSTEM_CONTEXT_SIZE 4096 * 10

struct myencfs_system_s;
typedef struct myencfs_system_s *myencfs_system;

struct myencfs_system_driver_entry_s {
	unsigned id;
	void (*f)();
};

size_t
myencfs_system_get_context_size(void);

myencfs_system
myencfs_system_new(void);

bool
myencfs_system_init(
	const myencfs_system system,
	const size_t size
);

bool
myencfs_system_construct(
	const myencfs_system system
);

bool
myencfs_system_destruct(
	const myencfs_system system
);

bool
myencfs_system_clean(
	const myencfs_system system,
	const size_t size
);

bool
myencfs_system_driver_register(
	const myencfs_system system,
	const struct myencfs_system_driver_entry_s * const entries
);

void (*myencfs_system_driver_find(
	const myencfs_system system,
	const unsigned id
))();

const void *
myencfs_system_get_userdata(
	const myencfs_system system
);

bool
myencfs_system_set_userdata(
	const myencfs_system system,
	const void *userdata
);

myencfs_error
myencfs_system_get_error(
	const myencfs_system system
);

void
myencfs_system_explicit_bzero(
	const myencfs_system system,
	void * const p,
	const size_t size
);

void *
myencfs_system_realloc(
	const myencfs_system system,
	const char * const hint,
	void * const p,
	const size_t size
);

bool
myencfs_system_free(
	const myencfs_system system,
	const char * const hint,
	void * const p
);

void *
myencfs_system_zalloc(
	const myencfs_system system,
	const char * const hint,
	const size_t size
);

char *
myencfs_system_strdup(
	const myencfs_system system,
	const char * const hint,
	const char * const s
);

#ifdef __cplusplus
}
#endif

#endif
