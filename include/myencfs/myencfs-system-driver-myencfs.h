#ifndef __MYENCFS_SYSTEM_DRIVER_MYENCFS_H
#define __MYENCFS_SYSTEM_DRIVER_MYENCFS_H

#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <myencfs/myencfs-system.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MYENCFS_SYSTEM_DRIVER_ID_<group>_<name> MSB_32bit(sha1(<group>_<name>)) */
#define MYENCFS_SYSTEM_DRIVER_ID_myencfs_mkdir 0x8ff2a9ab
#define MYENCFS_SYSTEM_DRIVER_ID_myencfs_access 0x18d36821

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYENCFS_SYSTEM_DRIVER_FUNC(myencfs, bool, mkdir, const char * const path, mode_t mode)
MYENCFS_SYSTEM_DRIVER_FUNC(myencfs, bool, access, const char * const path, int mode)
#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

#endif
