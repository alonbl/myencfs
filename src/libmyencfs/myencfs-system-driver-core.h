#ifndef __MYENCFS_SYSTEM_DRIVER_core_H
#define __MYENCFS_SYSTEM_DRIVER_core_H

#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <myencfs/myencfs-system-driver-ids-core.h>
#include <myencfs/myencfs-system.h>

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYENCFS_SYSTEM_DRIVER_FUNC(core, void, explicit_bzero, void * const s, size_t size)
MYENCFS_SYSTEM_DRIVER_FUNC(core, void *, realloc, const char * const hint, void * const p, size_t size)
MYENCFS_SYSTEM_DRIVER_FUNC(core, bool, free, const char * const hint, void * const p)
MYENCFS_SYSTEM_DRIVER_FUNC(core, bool, mkdir, const char * const path, mode_t mode)
MYENCFS_SYSTEM_DRIVER_FUNC(core, bool, access, const char * const path, int mode)
#pragma GCC diagnostic pop

#endif
