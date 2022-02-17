#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-bio-file.h>
#include <myencfs/myencfs-error.h>

#include "util.h"

static
bool
__key_callback(
	const myencfs myencfs,
	const char * const key_id,
	unsigned char * const key,
	const size_t key_size
) {
#if defined(ENABLE_ENCRYPT) || defined(ENABLE_DECRYPT)
	const char *keystore = (const char *)myencfs_context_get_user_context(myencfs_get_context(myencfs));
	myencfs_bio bio = NULL;
	char *path = NULL;
	bool ret = false;

	if (key_id == NULL) {
		goto cleanup;
	}

	if ((path = malloc(strlen(keystore) + strlen(key_id) + 2)) == NULL) {
		goto cleanup;
	}

	sprintf(path, "%s%c%s", keystore, _MYENCFS_PATH_SEPARTOR, key_id);

	if ((bio = myencfs_bio_file(myencfs_get_context(myencfs), path, "rb")) == NULL) {
		goto cleanup;
	}

	if (myencfs_bio_read(bio, key, key_size) != (ssize_t)key_size) {
		goto cleanup;
	}

	ret = true;

cleanup:

	myencfs_bio_destruct(bio);
	free(path);

	return ret;
#else
	(void)myencfs;
	(void)key_id;
	(void)key;
	(void)key_size;
	return false;
#endif
}

bool
_util_myencfs_set_keystore(
	const myencfs myencfs,
	const char * const keystore
) {
	bool ret = false;

	if (!myencfs_set_key_callback(myencfs, __key_callback)) {
		goto cleanup;
	}

	if (!myencfs_context_set_user_context(myencfs_get_context(myencfs), (void *)keystore)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}
