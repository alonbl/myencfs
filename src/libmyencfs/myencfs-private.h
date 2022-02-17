#ifndef __MYENCFS_PRIVATE_H
#define __MYENCFS_PRIVATE_H

#include "myencfs-error-internal.h"
#include "myencfs-internal.h"

myencfs_error_entry
__myencfs_error_entry_base(
	const myencfs myencfs,
	const myencfs_error_entry entry
);

myencfs_bio
__myencfs_file_open(
	const myencfs myencfs,
	const char * const mode,
	const char * const base,
	const char * const name,
	const char * const suffix
);

#endif
