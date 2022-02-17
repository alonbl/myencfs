#ifndef __MYENCFS_BIO_UTIL_H
#define __MYENCFS_BIO_UTIL_H

#include <stdint.h>

#include <myencfs/myencfs-bio.h>

ssize_t
_myencfs_bio_util_read_full_or_eof(
	const myencfs_bio bio,
	void * const _p,
	const size_t _s
);

ssize_t
_myencfs_bio_util_read_full(
	const myencfs_bio bio,
	void * const _p,
	const size_t _s
);

ssize_t
_myencfs_bio_util_write_full(
	const myencfs_bio bio,
	const void * const _p,
	const size_t _s
);

ssize_t
_myencfs_bio_util_read_uint32(
	const myencfs_bio bio,
	uint32_t * const u
);

ssize_t
_myencfs_bio_util_write_uint32(
	const myencfs_bio bio,
	const uint32_t u
);

ssize_t
_myencfs_bio_util_read_uint64(
	const myencfs_bio bio,
	uint64_t * const u
);

ssize_t
_myencfs_bio_util_write_uint64(
	const myencfs_bio bio,
	const uint64_t u
);

#endif
