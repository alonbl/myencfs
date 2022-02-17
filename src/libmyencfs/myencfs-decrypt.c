#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-bio-crypto.h>
#include <myencfs/myencfs-bio-file.h>

#include "myencfs-bio-crypto-internal.h"
#include "myencfs-bio-util.h"
#include "myencfs-md.h"
#include "myencfs-private.h"

myencfs_bio
myencfs_decrypt_bio(
	const myencfs myencfs,
	const size_t max_size,
	const char * const name
) {
#if defined(ENABLE_BIO_FILE)
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_bio bio_dec_pt = NULL;
	myencfs_bio bio_ct = NULL;
	myencfs_bio bio_md = NULL;
	myencfs_bio ret = NULL;

	if (myencfs_internal->base_ct == NULL) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"decrypt.sanity",
				MYENCFS_ERROR_CODE_STATE,
				true,
				"Base CT is not set"
			)
		));
		goto cleanup;
	}

	if ((bio_ct = __myencfs_file_open(
		myencfs,
		"rb",
		myencfs_internal->base_ct,
		name,
		NULL
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_md = __myencfs_file_open(
		myencfs,
		"rb",
		myencfs_internal->base_ct,
		name,
		myencfs_internal->md_suffix
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_bio_crypto_decrypt(myencfs)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_crypto_decrypt_init(
		bio_dec_pt,
		bio_ct,
		bio_md,
		max_size,
		name
	)) {
		goto cleanup;
	}

	{
		bool b = true;
		if (
			myencfs_bio_control(
				bio_dec_pt,
				_MYCRYPTFS_CRYPT_BIO_CMD_OWN_BIOS,
				&b, sizeof(b),
				NULL, 0
			) == -1
		) {
			_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
				myencfs,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_get_error(myencfs)),
					"decrypt.ownbios",
					MYENCFS_ERROR_CODE_RESOURCE_ACCESS,
					true,
					NULL
				)
			));
			goto cleanup;
		}
	}
	bio_ct = NULL;

	ret = bio_dec_pt;
	bio_dec_pt = NULL;

cleanup:

	myencfs_bio_destruct(bio_dec_pt);
	myencfs_bio_destruct(bio_ct);
	myencfs_bio_destruct(bio_md);

	return ret;
#else
	(void)max_size;
	(void)name;
	_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
		myencfs,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_get_error(myencfs)),
			"decrypt.bio",
			MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
			true,
			"bio-file is required for file operation but is not implemented"
		)
	));
	return NULL;
#endif
}

bool
myencfs_decrypt_file(
	const myencfs myencfs,
	const size_t max_size,
	const char * const name
) {
#if defined(ENABLE_BIO_FILE)
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_bio bio_pt = NULL;
	myencfs_bio bio_dec_pt = NULL;
	bool ret = false;

	if (myencfs == NULL) {
		return false;
	}

	if (myencfs_internal->base_pt == NULL) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"decrypt.sanity",
				MYENCFS_ERROR_CODE_STATE,
				true,
				"Base PT is not set"
			)
		));
		goto cleanup;
	}

	if ((bio_pt = __myencfs_file_open(
		myencfs,
		"wb",
		myencfs_internal->base_pt,
		name,
		NULL
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_decrypt_bio(
		myencfs,
		max_size,
		name
	)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(myencfs), bio_pt, bio_dec_pt, true)) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"decrypt.copy",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Failed to decrypt '%s'",
				name
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	/*
	 * TODO:
	 * Write to temp file and delete or rename at end.
	 */
	myencfs_bio_destruct(bio_pt);
	myencfs_bio_destruct(bio_dec_pt);

	return ret;
#else
	(void)max_size;
	(void)name;
	_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
		myencfs,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_get_error(myencfs)),
			"decrypt.bio",
			MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
			true,
			"bio-file is required for file operation but is not implemented"
		)
	));
	return false;
#endif
}

myencfs_info
myencfs_decrypt_info_bio(
	const myencfs myencfs,
	const myencfs_bio bio_md
) {
	myencfs_system system = myencfs_get_system(myencfs);
	_myencfs_md md[1];
	myencfs_info info = NULL;
	myencfs_info ret = NULL;

	if (!_myencfs_md_read(bio_md, md)) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"info.md",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Failed to read metadata fie"
			)
		));
		goto cleanup;
	}

	if ((info = myencfs_system_zalloc(system, "myencfs_info", sizeof(*info))) == NULL) {
		goto cleanup;
	}

	if ((info->key_id = myencfs_system_strdup(system, "myencfs_info.key_id", md->key_id)) == NULL) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"info.dup",
				MYENCFS_ERROR_CODE_MEMORY,
				true,
				NULL
			)
		));
		goto cleanup;
	}

	ret = info;
	info = NULL;

cleanup:

	myencfs_decrypt_free_info(myencfs, info);

	return ret;
}

myencfs_info
myencfs_decrypt_info_file(
	const myencfs myencfs,
	const char * const name
) {
#if defined(ENABLE_BIO_FILE)
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_bio bio_md = NULL;
	myencfs_info info = NULL;
	myencfs_info ret = NULL;

	if (myencfs == NULL) {
		return 0;
	}

	if ((bio_md = __myencfs_file_open(
		myencfs,
		"rb",
		myencfs_internal->base_ct,
		name,
		myencfs_internal->md_suffix
	)) == NULL) {
		goto cleanup;
	}

	if ((info = myencfs_decrypt_info_bio(myencfs, bio_md)) == NULL) {
		goto cleanup;
	}

	ret = info;
	info = NULL;

cleanup:

	myencfs_decrypt_free_info(myencfs, info);
	myencfs_bio_destruct(bio_md);

	return ret;
#else
	(void)name;
	_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
		myencfs,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_get_error(myencfs)),
			"decrypt.bio",
			MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
			true,
			"bio-file is required for file operation but is not implemented"
		)
	));
	return NULL;
#endif
}

bool
myencfs_decrypt_free_info(
	const myencfs myencfs,
	myencfs_info info
) {
	int ret = true;

	if (info != NULL) {
		myencfs_system system = myencfs_get_system(myencfs);

		ret = myencfs_system_free(system, "mycncfs_info::key_id", info->key_id) && ret;
		ret = myencfs_system_free(system, "myencfs_info", info) && ret;
	}

	return ret;
}
