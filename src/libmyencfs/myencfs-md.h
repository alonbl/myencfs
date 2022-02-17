#ifndef __MYENCFS_MD_H
#define __MYENCFS_MD_H

#include <stdint.h>

#include <myencfs/myencfs-bio.h>

#define _MYENCFS_MD_VERSION 1
#define _MYENCFS_MD_ALGO_AES256_GCM 1
#define _MYENCFS_MD_KEYID_SIZE 256

typedef struct _myencfs_md_s {
	uint32_t version;
	uint32_t algo;
	uint64_t size;
	char key_id[_MYENCFS_MD_KEYID_SIZE];
	unsigned char iv[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	unsigned char tag[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
} _myencfs_md;

bool
_myencfs_md_write_aad(
	const myencfs_bio bio,
	const _myencfs_md * const md,
	const char * const name
);

bool
_myencfs_md_read(
	const myencfs_bio bio,
	_myencfs_md * const md
);

bool
_myencfs_md_write(
	const myencfs_bio bio,
	const _myencfs_md * const md
);

#endif
