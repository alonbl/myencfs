#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "myencfs-bio-crypto-private.h"
#include "myencfs-bio-util.h"
#include "myencfs-error-internal.h"
#include "myencfs-internal.h"
#include "myencfs-md.h"
#include "myencfs-util.h"

typedef struct __bio_encrypt_private_s {
	struct {
		myencfs myencfs;
		myencfs_bio bio_random;
		_myencfs_crypto_cipher cipher;
		myencfs_bio bio_aad;
		size_t block_size;
		bool opened;
		int close_result;
	} init[1];
	struct {
		myencfs_bio bio_ct;
		myencfs_bio bio_md;
		_myencfs_md md[1];
		size_t total_size;
		unsigned char aad[__MYENCFS_BIO_CRYPTO_AAD_MAX_SIZE];
		size_t aad_size;
		unsigned char tail[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
		size_t tail_size;
		bool own_bios;
	} op[1];
} *__bio_encrypt_private;

static
myencfs_error_entry
__error_entry_base(
	const __bio_encrypt_private private,
	const myencfs_error_entry entry
) {
	if (private != NULL) {
		char buf[1024];
		_myencfs_error_entry_prm_add_str(
			entry,
			MYENCFS_ERROR_KEY_RESOURCE_NAME,
			_myencfs_util_snprintf(
				buf, sizeof(buf),
				"bio_crypto_encrypt::%s",
				myencfs_bio_get_name(private->op->bio_ct)
			)
		);
	}
	return entry;
}

static
int
__bio_encrypt_close(
	void *_private
) {
	__bio_encrypt_private private = (__bio_encrypt_private)_private;
	unsigned char buffer_ct[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	ssize_t len;
	int ret = -1;

	if (!private->init->opened) {
		return private->init->close_result;
	}

	if ((len = _myencfs_crypto_cipher_final(
		private->init->cipher,
		private->op->tail,
		private->op->tail_size,
		buffer_ct, sizeof(buffer_ct)
	)) == -1) {
		goto cleanup;
	}

	if (_myencfs_bio_util_write_full(
		private->op->bio_ct,
		buffer_ct,
		len
	) == -1) {
		goto cleanup;
	}
	private->op->total_size += len;

	if (!_myencfs_md_write(private->op->bio_md, private->op->md)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"md.write",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot write metadata"
			)
		));
		goto cleanup;
	}

	private->init->close_result = ret = 0;

cleanup:

	private->init->opened = false;
	myencfs_bio_close(private->op->bio_ct);
	myencfs_bio_close(private->op->bio_md);

	return ret;
}

static
bool
__bio_encrypt_destruct(
	void *_private
) {
	__bio_encrypt_private private = (__bio_encrypt_private)_private;
	bool ret = true;

	if (private != NULL) {
		myencfs_system system = myencfs_get_system(private->init->myencfs);

		if (__bio_encrypt_close(private) != 0) {
			ret = false;
		}

		if (private->op->own_bios) {
			ret = myencfs_bio_destruct(private->op->bio_ct) && ret;
			ret = myencfs_bio_destruct(private->op->bio_md) && ret;
		}

		ret = myencfs_bio_destruct(private->init->bio_aad) && ret;
		ret = _myencfs_crypto_cipher_destruct(private->init->cipher) && ret;

		ret = myencfs_system_free(system, "myencfs_bio_encrypt", private) && ret;
	}

	return ret;
}

static
ssize_t
__bio_encrypt_write(
	void *_private,
	const void * const _buf,
	const size_t _size
) {
	__bio_encrypt_private private = (__bio_encrypt_private)_private;
	const unsigned char *buf = _buf;
	size_t size = _size;
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

	if (private->op->tail_size != 0) {
		unsigned char buffer_ct[sizeof(private->op->tail)];
		size_t n;
		ssize_t len;

		n = _MYENCFS_UTIL_MIN(size, private->init->block_size - private->op->tail_size);

		memcpy(
			private->op->tail + private->op->tail_size,
			buf,
			n
		);
		private->op->tail_size += n;
		buf += n;
		size -= n;

		if (private->op->tail_size == private->init->block_size) {
			if ((len = _myencfs_crypto_cipher_update(
				private->init->cipher,
				private->op->tail,
				private->op->tail_size,
				buffer_ct,
				sizeof(buffer_ct)
			)) == -1) {
				goto cleanup;
			}

			if (_myencfs_bio_util_write_full(
				private->op->bio_ct,
				buffer_ct,
				len
			) == -1) {
				goto cleanup;
			}
			private->op->tail_size -= len;
		}
	}

	while (size >= private->init->block_size) {
		unsigned char buffer_ct[_MYENCFS_IO_BLOCK_SIZE];
		ssize_t len;
		size_t n;

		assert(private->init->block_size > 0);	// scan-build: divide-by-zero
		n = _MYENCFS_UTIL_MIN(size, sizeof(buffer_ct));
		n -= (n % private->init->block_size);

		if ((len = _myencfs_crypto_cipher_update(
			private->init->cipher,
			buf,
			n,
			buffer_ct,
			sizeof(buffer_ct)
		)) == -1) {
			goto cleanup;
		}

		if (_myencfs_bio_util_write_full(
			private->op->bio_ct,
			buffer_ct,
			len
		) == -1) {
			goto cleanup;
		}

		buf += len;
		size -= len;
	}

	memcpy(private->op->tail + private->op->tail_size, buf, size);
	private->op->tail_size += size;

	private->op->total_size += _size;
	ret = _size;

cleanup:

	return ret;
}

static
ssize_t
__bio_encrypt_tell(
	void *_private
) {
	__bio_encrypt_private private = (__bio_encrypt_private)_private;
	return private->op->total_size;
}

static
ssize_t
__bio_encrypt_control(
	void *_private,
	const int command,
	const void * const in,
	const size_t in_size,
	void * const out,
	const size_t out_size
) {
	__bio_encrypt_private private = (__bio_encrypt_private)_private;
	ssize_t ret = -1;

	switch (command) {
		default:
			_myencfs_error_entry_dispatch(__error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
					"read.opened",
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
						"control.get_private",
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

static myencfs_bio_callbacks __myencfs_bio_callbacks_encrypt = {
	__bio_encrypt_destruct,
	__bio_encrypt_close,
	NULL,
	__bio_encrypt_write,
	NULL,
	__bio_encrypt_tell,
	__bio_encrypt_control
};

myencfs_bio
myencfs_bio_crypto_encrypt(
	const myencfs myencfs
) {
	myencfs_internal myencfs_internal = _myencfs_get_internal(myencfs);
	myencfs_system system = myencfs_get_system(myencfs);
	__bio_encrypt_private private = NULL;
	myencfs_bio bio_enc_pt = NULL;
	myencfs_bio ret = NULL;

	if ((private = myencfs_system_zalloc(system, "myencfs_bio_crypto_encrypt", sizeof(*private))) == NULL) {
		goto cleanup;
	}

	private->init->myencfs = myencfs;
	private->init->bio_random = myencfs_internal->bio_random;

	if ((private->init->cipher = _myencfs_crypto_cipher_new(myencfs_internal->crypto)) == NULL) {
		goto cleanup;
	}

	if (!_myencfs_crypto_cipher_construct(private->init->cipher)) {
		goto cleanup;
	}

	private->init->block_size = _myencfs_crypto_cipher_get_cipher_block_size(private->init->cipher);

	if ((private->init->bio_aad = myencfs_bio_mem_buf(
		myencfs_get_context(myencfs),
		"aad",
		private->op->aad,
		0,
		sizeof(private->op->aad)
	)) == NULL) {
		goto cleanup;
	}

	if ((bio_enc_pt = myencfs_bio_new(myencfs_get_context(myencfs))) == NULL) {
		goto cleanup;
	}

	if (
		!myencfs_bio_construct(
			bio_enc_pt,
			"bio_crypto_encrypt",
			&__myencfs_bio_callbacks_encrypt,
			sizeof(__myencfs_bio_callbacks_encrypt),
			private
		)
	) {
		goto cleanup;
	}
	private = NULL;

	ret = bio_enc_pt;
	bio_enc_pt = NULL;

cleanup:

	__bio_encrypt_destruct(private);
	myencfs_bio_destruct(bio_enc_pt);

	return ret;
}

bool
myencfs_bio_crypto_encrypt_init(
	const myencfs_bio bio_enc_pt,
	const myencfs_bio bio_ct,
	const myencfs_bio bio_md,
	const char * const name,
	const size_t pt_size
) {
	myencfs_internal myencfs_internal;
	myencfs_system system;
	__bio_encrypt_private private = NULL;
	unsigned char key[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	size_t key_size;
	size_t iv_size;
	size_t tag_size;
	bool ret = false;

	if (bio_enc_pt == NULL) {
		return false;
	}

	system = myencfs_context_get_system(myencfs_bio_get_context(bio_enc_pt));

	if (
		myencfs_bio_control(
			bio_enc_pt,
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

	private->op->bio_ct = bio_ct;
	private->op->bio_md = bio_md;

	memset(private->op->md, 0, sizeof(private->op->md));
	private->op->md->version = _MYENCFS_MD_VERSION;
	private->op->md->algo = _MYENCFS_MD_ALGO_AES256_GCM;
	private->op->md->size = pt_size;
	if (myencfs_internal->encryption_key_id != NULL) {
		strncpy(
			private->op->md->key_id,
			myencfs_internal->encryption_key_id,
			sizeof(private->op->md->key_id) - 1
		);
	}

	key_size = _myencfs_crypto_cipher_get_cipher_key_size(private->init->cipher);
	iv_size = _myencfs_crypto_cipher_get_cipher_iv_size(private->init->cipher);
	tag_size = _myencfs_crypto_cipher_get_cipher_tag_size(private->init->cipher);

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
	if (private->init->block_size > sizeof(private->op->tail)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"sanity",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"block size too large expected=%d actual=%d",
				(int)sizeof(private->op->tail),
				(int)private->init->block_size
			)
		));
		goto cleanup;
	}

	if (myencfs_bio_read(myencfs_internal->bio_random, private->op->md->iv, iv_size) != (ssize_t)iv_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_get_error(private->init->myencfs)),
				"iv.gen",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Failed generating IV"
			)
		));
		goto cleanup;
	}

	if (!_myencfs_md_write_aad(private->init->bio_aad, private->op->md, name)) {
		goto cleanup;
	}
	private->op->aad_size = myencfs_bio_mem_get_data(private->init->bio_aad, NULL);

	if (!myencfs_internal->key_callback(private->init->myencfs, private->op->md->key_id, key, key_size)) {
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

	if (!_myencfs_crypto_cipher_init(
		private->init->cipher,
		true,
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
