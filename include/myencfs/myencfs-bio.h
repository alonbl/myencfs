#ifndef __MYENCFS_BIO_H
#define __MYENCFS_BIO_H

#include <stdlib.h>
#include <stdbool.h>

#include <myencfs/myencfs-context.h>

#ifdef __cplusplus
extern "C" {
#endif

struct __myencfs_bio_s;
typedef struct __myencfs_bio_s *myencfs_bio;

/* TODO: switch to callback vector */
typedef struct myencfs_bio_callbacks_s {
	bool (*destruct)(
		void *context
	);
	int (*close)(
		void *context
	);
	ssize_t (*read)(
		void *context,
		void * const buf,
		const size_t size
	);
	ssize_t (*write)(
		void *context,
		const void * const buf,
		const size_t size
	);
	int (*seek)(
		void *context,
		ssize_t offset,
		int whence
	);
	ssize_t (*tell)(
		void *context
	);
	ssize_t (*control)(
		void *context,
		const int command,
		const void * const in,
		const size_t in_size,
		void * const out,
		const size_t out_size
	);
} myencfs_bio_callbacks;

bool
myencfs_bio_copy(
	const myencfs_context context,
	const myencfs_bio dst,
	const myencfs_bio src,
	const bool do_close
);

myencfs_bio
myencfs_bio_new(
	const myencfs_context context
);

bool
myencfs_bio_construct(
	const myencfs_bio bio,
	const char * const name,
	const myencfs_bio_callbacks *const callbacks,
	const size_t callbacks_size,
	void *context
);

bool
myencfs_bio_destruct(
	const myencfs_bio bio
);

myencfs_context
myencfs_bio_get_context(
	const myencfs_bio bio
);

const char *
myencfs_bio_get_name(
	const myencfs_bio bio
);

int
myencfs_bio_close(
	const myencfs_bio bio
);

ssize_t
myencfs_bio_read(
	const myencfs_bio bio,
	void * const buf,
	const size_t size
);

ssize_t
myencfs_bio_write(
	const myencfs_bio bio,
	const void * const buf,
	const size_t size
);

int
myencfs_bio_seek(
	const myencfs_bio bio,
	ssize_t offset,
	int whence
);

ssize_t
myencfs_bio_tell(
	const myencfs_bio bio
);

ssize_t
myencfs_bio_control(
	const myencfs_bio bio,
	const int command,
	const void * const in,
	const size_t in_size,
	void * const out,
	const size_t out_size
);

myencfs_bio
myencfs_bio_null(
	const myencfs_context context
);

myencfs_bio
myencfs_bio_mem(
	const myencfs_context context,
	const char * const name
);

myencfs_bio
myencfs_bio_mem_buf(
	const myencfs_context context,
	const char * const name,
	unsigned char * const buf,
	const size_t size,
	const size_t max_size
);

bool
myencfs_bio_mem_reset(
	const myencfs_bio bio
);

size_t
myencfs_bio_mem_get_data(
	const myencfs_bio bio,
	void **p
);

size_t
myencfs_bio_mem_get_max_size(
	const myencfs_bio bio,
	void **p
);

#ifdef __cplusplus
}
#endif

#endif
