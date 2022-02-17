#ifndef __MYENCFS_H
#define __MYENCFS_H

#include <stdbool.h>
#include <stdlib.h>

#include "myencfs-bio.h"
#include "myencfs-context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MYENCFS_MD_MAX_SIZE 1024

struct __myencfs_s;
typedef struct __myencfs_s *myencfs;

/* TODO: switch to callback vector */
typedef bool (*myencfs_key_callback)(
	const myencfs myencfs,
	const char * const key_id,
	unsigned char * const key,
	const size_t key_size
);

typedef struct myencfs_info_s {
	char *key_id;
} *myencfs_info;

myencfs
myencfs_new(
	const myencfs_context context
);

bool
myencfs_construct(
	const myencfs myencfs
);

bool
myencfs_destruct(
	const myencfs myencfs
);

myencfs_context
myencfs_get_context(
	const myencfs myencfs
);

myencfs_system
myencfs_get_system(
	const myencfs myencfs
);

myencfs_error
myencfs_get_error(
	const myencfs myencfs
);

bool
myencfs_set_base_ct(
	const myencfs myencfs,
	const char * const base_ct
);

bool
myencfs_set_base_pt(
	const myencfs myencfs,
	const char * const base_pt
);

bool
myencfs_set_key_callback(
	const myencfs myencfs,
	const myencfs_key_callback callback
);

bool
myencfs_set_encryption_key_id(
	const myencfs myencfs,
	const char * const key_id
);

const char *
myencfs_get_md_suffix(
	const myencfs myencfs
);

bool
myencfs_set_md_suffix(
	const myencfs myencfs,
	const char * const suffix
);

myencfs_bio
myencfs_encrypt_bio(
	const myencfs myencfs,
	const char * const name,
	const size_t pt_size
);

bool
myencfs_encrypt_file(
	const myencfs myencfs,
	const char * const name
);

myencfs_bio
myencfs_decrypt_bio(
	const myencfs myencfs,
	const size_t max_size,
	const char * const name
);

bool
myencfs_decrypt_file(
	const myencfs myencfs,
	const size_t max_size,
	const char * const name
);

myencfs_info
myencfs_decrypt_info_bio(
	const myencfs myencfs,
	const myencfs_bio bio_md
);

myencfs_info
myencfs_decrypt_info_file(
	const myencfs myencfs,
	const char * const name
);

bool
myencfs_decrypt_free_info(
	const myencfs myencfs,
	myencfs_info info
);

#ifdef __cplusplus
}
#endif

#endif
