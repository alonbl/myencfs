#ifndef __MYENCFS_INTERNAL_H
#define __MYENCFS_INTERNAL_H

#include <myencfs/myencfs.h>

#include "myencfs-crypto.h"

struct _myencfs_internal_s {
	char *base_ct;
	char *base_pt;
	char *md_suffix;
	_myencfs_crypto crypto;
	myencfs_key_callback key_callback;
	char *encryption_key_id;
};
typedef struct _myencfs_internal_s *myencfs_internal;

myencfs_internal
_myencfs_get_internal(
	const myencfs myencfs
);

#endif
