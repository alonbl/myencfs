#ifndef __MYENCFS_SYSTEM_DRIVER_CORE_H
#define __MYENCFS_SYSTEM_DRIVER_CORE_H

#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <myencfs/myencfs-system.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MYENCFS_SYSTEM_DRIVER_ID_<group>_<name> MSB_32bit(sha1(<group>_<name>)) */
#define MYENCFS_SYSTEM_DRIVER_ID_core_explicit_bzero 0xf6ac4e65
#define MYENCFS_SYSTEM_DRIVER_ID_core_free 0x4e483569
#define MYENCFS_SYSTEM_DRIVER_ID_core_realloc 0xc4a51b02

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYENCFS_SYSTEM_DRIVER_FUNC(core, void, explicit_bzero, void * const s, size_t size)
MYENCFS_SYSTEM_DRIVER_FUNC(core, void *, realloc, const char * const hint, void * const p, size_t size)
MYENCFS_SYSTEM_DRIVER_FUNC(core, bool, free, const char * const hint, void * const p)
#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

#endif
