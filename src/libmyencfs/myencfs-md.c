#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "myencfs-bio-util.h"
#include "myencfs-md.h"

bool
_myencfs_md_write_aad(
	const myencfs_bio bio,
	const _myencfs_md * const md,
	const char * const name
) {
	bool ret = false;

	if (_myencfs_bio_util_write_uint32(bio, md->version) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_uint32(bio, md->algo) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_uint64(bio, md->size) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_uint32(bio, strlen(name)) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_full(bio, (char *)name, strlen(name)) == -1) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_myencfs_md_read(
	const myencfs_bio bio,
	_myencfs_md * const md
) {
	bool ret = false;

	memset(md, 0, sizeof(*md));

	if (_myencfs_bio_util_read_uint32(bio, &md->version) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_read_uint32(bio, &md->algo) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_read_uint64(bio, &md->size) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_read_full(bio, md->key_id, sizeof(md->key_id)) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_read_full(bio, md->iv, sizeof(md->iv)) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_read_full(bio, md->tag, sizeof(md->tag)) == -1) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_myencfs_md_write(
	const myencfs_bio bio,
	const _myencfs_md * const md
) {
	bool ret = false;

	if (_myencfs_bio_util_write_uint32(bio, md->version) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_uint32(bio, md->algo) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_uint64(bio, md->size) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_full(bio, md->key_id, sizeof(md->key_id)) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_full(bio, md->iv, sizeof(md->iv)) == -1) {
		goto cleanup;
	}
	if (_myencfs_bio_util_write_full(bio, md->tag, sizeof(md->tag)) == -1) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}
