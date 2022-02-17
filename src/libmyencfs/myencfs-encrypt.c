#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-bio-crypto.h>
#include <myencfs/myencfs-bio-file.h>

#include "myencfs-bio-crypto-internal.h"
#include "myencfs-bio-util.h"
#include "myencfs-private.h"

myencfs_bio
myencfs_encrypt_bio(
	const myencfs myencfs,
	const char * const name,
	const size_t pt_size
) {
#if defined(ENABLE_BIO_FILE)
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_bio bio_enc_pt = NULL;
	myencfs_bio bio_ct = NULL;
	myencfs_bio bio_md = NULL;
	myencfs_bio ret = NULL;

	if (myencfs == NULL) {
		return NULL;
	}

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
		"wb",
		myencfs_internal->base_ct,
		name,
		NULL
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_md = __myencfs_file_open(
		myencfs,
		"wb",
		myencfs_internal->base_ct,
		name,
		myencfs_internal->md_suffix
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_enc_pt = myencfs_bio_crypto_encrypt(myencfs)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_crypto_encrypt_init(
		bio_enc_pt,
		bio_ct,
		bio_md,
		name,
		pt_size
	)) {
		goto cleanup;
	}

	{
		bool b = true;
		if (
			myencfs_bio_control(
				bio_enc_pt,
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
	bio_md = NULL;

	ret = bio_enc_pt;
	bio_enc_pt = NULL;

cleanup:

	/*
	 * TODO:
	 * Write to temp file and delete or rename at end.
	 */
	myencfs_bio_destruct(bio_enc_pt);
	myencfs_bio_destruct(bio_ct);
	myencfs_bio_destruct(bio_md);

	return ret;
#else
	(void)name;
	(void)pt_size;
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
myencfs_encrypt_file(
	const myencfs myencfs,
	const char * const name
) {
#if defined(ENABLE_BIO_FILE)
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_bio bio_pt = NULL;
	myencfs_bio bio_enc_pt = NULL;
	size_t pt_size;
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
		"rb",
		myencfs_internal->base_pt,
		name, NULL
	)) == NULL) {
		goto cleanup;
	}
	{
		ssize_t n;
		if (myencfs_bio_seek(bio_pt, 0, SEEK_END) == -1) {
			goto cleanup;
		}
		if  ((n = myencfs_bio_tell(bio_pt)) == -1) {
			goto cleanup;
		}
		pt_size = (size_t)n;
		if (myencfs_bio_seek(bio_pt, 0, SEEK_SET) == -1) {
			goto cleanup;
		}
	}

	if ((bio_enc_pt = myencfs_encrypt_bio(
		myencfs,
		name,
		pt_size
	)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(myencfs), bio_enc_pt, bio_pt, true)) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(myencfs)),
				"decrypt.copy",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Failed to encrypt '%s'",
				name
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	myencfs_bio_destruct(bio_pt);
	myencfs_bio_destruct(bio_enc_pt);

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
	return false;
#endif
}
