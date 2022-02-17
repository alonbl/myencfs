#ifndef __MYENCFS_CONTEXT_H
#define __MYENCFS_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "myencfs-error.h"
#include "myencfs-system.h"


#ifdef __cplusplus
extern "C" {
#endif

struct __myencfs_context_s;
typedef struct __myencfs_context_s *myencfs_context;

myencfs_context
myencfs_context_new(
	const myencfs_system system
);

bool
myencfs_context_construct(
	const myencfs_context context
);

bool
myencfs_context_destruct(
	const myencfs_context context
);

myencfs_system
myencfs_context_get_system(
	const myencfs_context context
);

const void *
myencfs_context_get_user_context(
	const myencfs_context context
);

bool
myencfs_context_set_user_context(
	const myencfs_context context,
	void *user_context
);

myencfs_error
myencfs_context_get_error(
	const myencfs_context context
);

void
myencfs_context_error_reset(
	const myencfs_context context
);

#ifdef __cplusplus
}
#endif

#endif
