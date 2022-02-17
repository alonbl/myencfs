#ifndef __MYENCFS_STATIC_H
#define __MYENCFS_STATIC_H

#include "myencfs-system.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
myencfs_static_init(
	const myencfs_system system
);

bool
myencfs_static_clean(
	const myencfs_system system
);

#ifdef __cplusplus
}
#endif

#endif
