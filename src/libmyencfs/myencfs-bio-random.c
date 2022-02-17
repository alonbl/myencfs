#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "myencfs-bio-random.h"
#include "myencfs-error-internal.h"
#include "myencfs-util.h"

typedef struct __random_private_s {
	myencfs_context context;
	_myencfs_crypto crypto;
} *__random_private;

static
bool
__random_destruct(
	void *_private
) {
	__random_private private = (__random_private)_private;
	bool ret = true;

	if (private != NULL) {
		myencfs_system system = myencfs_context_get_system(private->context);

		ret = myencfs_system_free(system, "myencfs_bio_random", private) && ret;
	}

	return ret;
}

static
ssize_t
__random_read(
	void *_private,
	void * const buf,
	const size_t size
) {
	__random_private private = (__random_private)_private;

	return _myencfs_crypto_rand_bytes(private->crypto, buf, size) ? (ssize_t)size : -1;
}

static myencfs_bio_callbacks __myencfs_bio_callbacks_random = {
	__random_destruct,
	NULL,
	__random_read,
	NULL,
	NULL,
	NULL,
	NULL
};

myencfs_bio
_myencfs_bio_random(
	const myencfs_context context,
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(context);
	myencfs_bio bio = NULL;
	__random_private private = NULL;
	myencfs_bio ret = NULL;

	if ((private = myencfs_system_zalloc(system, "myencfs_bio_random", sizeof(*private))) == NULL) {
		goto cleanup;
	}

	private->context = context;
	private->crypto = crypto;

	if ((bio = myencfs_bio_new(context)) == NULL) {
		goto cleanup;
	}

	if (
		!myencfs_bio_construct(
			bio,
			"bio_random",
			&__myencfs_bio_callbacks_random,
			sizeof(__myencfs_bio_callbacks_random),
			private
		)
	) {
		goto cleanup;
	}
	private = NULL;

	ret = bio;
	bio = NULL;

cleanup:

	myencfs_bio_destruct(bio);
	__random_destruct(private);

	return ret;
}
