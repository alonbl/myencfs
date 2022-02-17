#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "myencfs-bio-crypto-private.h"
#include "myencfs-bio-util.h"
#include "myencfs-error-internal.h"
#include "myencfs-internal.h"
#include "myencfs-md.h"
#include "myencfs-util.h"

typedef struct __bio_decrypt_private_s {
	struct {
		myencfs myencfs;
		_myencfs_crypto_operation op;
		myencfs_bio bio_aad;
		size_t block_size;
		bool opened;
		int close_result;
	} init[1];
	struct {
		myencfs_bio bio_ct;
		_myencfs_md md[1];
		size_t max_size;
		size_t total_size;
		unsigned char aad[__MYENCFS_BIO_CRYPTO_AAD_MAX_SIZE];
		size_t aad_size;
		unsigned char work[_MYENCFS_IO_BLOCK_SIZE];
		unsigned char *work_p;
		size_t work_s;
		bool work_eof;
		bool own_bios;
	} op[1];
} *__bio_decrypt_private;

static
myencfs_error_entry
__error_entry_base(
	const __bio_decrypt_private private,
	const myencfs_error_entry entry
) {
	if (private != NULL) {
		char buf[1024];
		_myencfs_error_entry_prm_add_str(
			entry,
			MYENCFS_ERROR_KEY_RESOURCE_NAME,
			_myencfs_util_snprintf(
				buf, sizeof(buf),
				"bio_crypto_decrypt::%s",
				myencfs_bio_get_name(private->op->bio_ct)
			)
		);
	}
	return entry;
}

static
int
__bio_decrypt_close(
	void *_private
) {
	__bio_decrypt_private private = (__bio_decrypt_private)_private;
	int ret = -1;

	if (!private->init->opened) {
		return private->init->close_result;
	}

	if (private->op->total_size != private->op->md->size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"integrity.size",
				MYENCFS_ERROR_CODE_ARGS,
				false,
				"The plaintext size is incorrect"
			)
		));
		goto cleanup;
	}

	private->init->close_result = ret = 0;

cleanup:

	private->init->opened = false;
	myencfs_bio_close(private->op->bio_ct);

	return ret;
}

static
bool
__bio_decrypt_destruct(
	void *_private
) {
	__bio_decrypt_private private = (__bio_decrypt_private)_private;
	bool ret = true;

	if (private != NULL) {
		myencfs_system system = myencfs_get_system(private->init->myencfs);

		__bio_decrypt_close(private);
		if (private->op->own_bios) {
			if (!myencfs_bio_destruct(private->op->bio_ct)) {
				ret = false;
			}
		}

		if (
			!myencfs_bio_destruct(private->init->bio_aad) ||
			!_myencfs_crypto_operation_destruct(private->init->op)
		) {
			ret = false;
		}

		if (!myencfs_system_free(system, "myencfs_bio_decrypt", private)) {
			ret = false;
		}
	}

	return ret;
}

static
ssize_t
__bio_decrypt_read(
	void *_private,
	void * const _buf,
	const size_t _size
) {
	__bio_decrypt_private private = (__bio_decrypt_private)_private;
	unsigned char *buf = _buf;
	size_t size = _size;
	size_t total = 0;
	ssize_t ret = -1;

	if (!private->init->opened) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"read.opened",
				MYENCFS_ERROR_CODE_STATE,
				true,
				"Attempt to write to closed bio"
			)
		));
		goto cleanup;
	}

	while (size > 0 && !(private->op->work_s == 0 && private->op->work_eof)) {
		if (private->op->work_s == 0) {
			unsigned char buffer_ct[sizeof(private->op->work)];
			ssize_t len;
			ssize_t n;

			if ((n = _myencfs_bio_util_read_full_or_eof(
				private->op->bio_ct,
				buffer_ct,
				sizeof(buffer_ct)
			)) == -1) {
				goto cleanup;
			}

			if (n == sizeof(buffer_ct)) {
				if ((len = _myencfs_crypto_operation_decrypt_update(
					private->init->op,
					buffer_ct,
					n,
					private->op->work,
					sizeof(private->op->work)
				)) == -1) {
					goto cleanup;
				}
			}
			else {
				if ((len = _myencfs_crypto_operation_decrypt_final(
					private->init->op,
					buffer_ct,
					n,
					private->op->work,
					sizeof(private->op->work)
				)) == -1) {
					goto cleanup;
				}
				private->op->work_eof = true;
			}

			private->op->work_p = private->op->work;
			private->op->work_s = len;
		}

		{
			size_t len = _MYENCFS_UTIL_MIN(size,  private->op->work_s);

			if (private->op->total_size + len > private->op->max_size) {
				_myencfs_error_entry_dispatch(__error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
						"read",
						MYENCFS_ERROR_CODE_IO,
						true,
						"Plaintext size is greater than maximum %ld",
						(long)private->op->max_size
					)
				));
				goto cleanup;
			}

			memcpy(buf, private->op->work_p, len);

			private->op->work_p += len;
			private->op->work_s -= len;
			buf += len;
			size -= len;
			total += len;
		}
	}

	private->op->total_size += total;
	ret = total;

cleanup:

	return ret;
}

static
ssize_t
__bio_decrypt_tell(
	void *_private
) {
	__bio_decrypt_private private = (__bio_decrypt_private)_private;
	return private->op->total_size;
}

static
ssize_t
__bio_decrypt_control(
	void *_private,
	const int command,
	const void * const in,
	const size_t in_size,
	void * const out,
	const size_t out_size
) {
	__bio_decrypt_private private = (__bio_decrypt_private)_private;
	ssize_t ret = -1;

	switch (command) {
		default:
			_myencfs_error_entry_dispatch(__error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
					"control.command",
					MYENCFS_ERROR_CODE_ARGS,
					true,
					"Invalid control command %d",
					command
				)
			));
			goto cleanup;
		case __MYCRYPTFS_CRYPT_BIO_CMD_GET_PRIVATE:
			if (out_size < sizeof(void *)) {
				_myencfs_error_entry_dispatch(__error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
						"control.get_private",
						MYENCFS_ERROR_CODE_ARGS,
						true,
						"Output buffer is too small"
					)
				));
				goto cleanup;
			}
			*(void **)out = private;
			ret = sizeof(void *);
		break;
		case _MYCRYPTFS_CRYPT_BIO_CMD_OWN_BIOS:
			if (in_size < sizeof(bool)) {
				_myencfs_error_entry_dispatch(__error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
						"control.own_bios",
						MYENCFS_ERROR_CODE_ARGS,
						true,
						"Input buffer is too small"
					)
				));
				goto cleanup;
			}
			private->op->own_bios = *(bool *)in;
			ret = sizeof(bool);
		break;
	}

cleanup:

	return ret;
}

static myencfs_bio_callbacks __myencfs_bio_callbacks_decrypt = {
	__bio_decrypt_destruct,
	__bio_decrypt_close,
	__bio_decrypt_read,
	NULL,
	NULL,
	__bio_decrypt_tell,
	__bio_decrypt_control
};

myencfs_bio
myencfs_bio_crypto_decrypt(
	const myencfs myencfs
) {
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_system system = myencfs_get_system(myencfs);
	__bio_decrypt_private private = NULL;
	myencfs_bio bio_dec_pt = NULL;
	myencfs_bio ret = NULL;

	if ((private = myencfs_system_zalloc(system, "myencfs_bio_crypto_decrypt", sizeof(*private))) == NULL) {
		goto cleanup;
	}

	private->init->myencfs = myencfs;

	if ((private->init->op = _myencfs_crypto_operation_new(myencfs_internal->crypto)) == NULL) {
		goto cleanup;
	}

	if (!_myencfs_crypto_operation_construct(private->init->op)) {
		goto cleanup;
	}

	private->init->block_size = _myencfs_crypto_operation_get_cipher_block_size(private->init->op);

	if ((private->init->bio_aad = myencfs_bio_mem_buf(
		myencfs_get_context(myencfs),
		"aad",
		private->op->aad,
		0,
		sizeof(private->op->aad)
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_bio_new(myencfs_get_context(myencfs))) == NULL) {
		goto cleanup;
	}

	if (
		!myencfs_bio_construct(
			bio_dec_pt,
			"bio_crypto_decrypt",
			&__myencfs_bio_callbacks_decrypt,
			sizeof(__myencfs_bio_callbacks_decrypt),
			private
		)
	) {
		goto cleanup;
	}
	private = NULL;

	ret = bio_dec_pt;
	bio_dec_pt = NULL;

cleanup:

	myencfs_bio_destruct(bio_dec_pt);
	__bio_decrypt_destruct(private);

	return ret;
}

bool
myencfs_bio_crypto_decrypt_init(
	const myencfs_bio bio_dec_pt,
	const myencfs_bio bio_ct,
	const myencfs_bio bio_md,
	const size_t max_size,
	const char * const name
) {
	myencfs_internal myencfs_internal;
	myencfs_system system;
	__bio_decrypt_private private = NULL;
	unsigned char key[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	size_t key_size;
	size_t iv_size;
	size_t tag_size;
	bool ret = false;

	system = myencfs_context_get_system(myencfs_bio_get_context(bio_dec_pt));

	if (
		myencfs_bio_control(
			bio_dec_pt,
			__MYCRYPTFS_CRYPT_BIO_CMD_GET_PRIVATE,
			NULL, 0,
			&private, sizeof(private)
		) == -1
	) {
		goto cleanup;
	}

	myencfs_internal = _myencfs_get_internal(private->init->myencfs);

	memset(private->op, 0, sizeof(private->op));

	myencfs_bio_mem_reset(private->init->bio_aad);

	if (!_myencfs_md_read(bio_md, private->op->md)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"decrypt.init",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot read metadata"
			)
		));
		goto cleanup;
	}

	if (private->op->md->version != _MYENCFS_MD_VERSION) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"decrypt.init",
				MYENCFS_ERROR_CODE_STATE,
				true,
				"Metadata version mismatch expected=%d actual=%d",
				_MYENCFS_MD_VERSION,
				private->op->md->version
			)
		));
		goto cleanup;
	}
	if (private->op->md->algo != _MYENCFS_MD_ALGO_AES256_GCM) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"decrypt.init",
				MYENCFS_ERROR_CODE_STATE,
				true,
				"Algorithm mismatch expected=%d actual=%d",
				_MYENCFS_MD_ALGO_AES256_GCM,
				private->op->md->algo
			)
		));
		goto cleanup;
	}

	private->op->bio_ct = bio_ct;
	private->op->max_size = _MYENCFS_UTIL_MIN(max_size, private->op->md->size);

	key_size = _myencfs_crypto_operation_get_cipher_key_size(private->init->op);
	iv_size = _myencfs_crypto_operation_get_cipher_iv_size(private->init->op);
	tag_size = _myencfs_crypto_operation_get_cipher_tag_size(private->init->op);

	if (iv_size > sizeof(private->op->md->iv)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"sanity",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"iv size mismatch expected=%d actual=%d",
				(int)sizeof(private->op->md->iv),
				(int)iv_size
			)
		));
		goto cleanup;
	}
	if (tag_size > sizeof(private->op->md->tag)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"sanity",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"tag size mismatch expected=%d actual=%d",
				(int)sizeof(private->op->md->tag),
				(int)tag_size
			)
		));
		goto cleanup;
	}

	if (!_myencfs_md_write_aad(private->init->bio_aad, private->op->md, name)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"sanity",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot write metadata"
			)
		));
		goto cleanup;
	}
	private->op->aad_size = myencfs_bio_mem_get_data(private->init->bio_aad, NULL);

	if (!myencfs_internal->key_callback(
		private->init->myencfs,
		private->op->md->key_id,
		key,
		key_size
	)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"key.callback",
				MYENCFS_ERROR_CODE_NO_KEY,
				true,
				"Key id '%s' is not available",
				private->op->md->key_id
			)
		));
		goto cleanup;
	}

	if (!_myencfs_crypto_operation_decrypt_init(
		private->init->op,
		key, key_size,
		private->op->md->iv, iv_size,
		private->op->aad, private->op->aad_size,
		private->op->md->tag, tag_size
	)) {
		goto cleanup;
	}

	private->init->opened = true;
	ret = true;

cleanup:

	myencfs_system_explicit_bzero(system, key, sizeof(key));

	return ret;
}
