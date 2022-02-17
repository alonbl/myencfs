#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#include "myencfs-crypto.h"
#include "myencfs-error-internal.h"

struct __myencfs_crypto_s {
	myencfs_context context;
	WC_RNG rng[1];
};

struct __myencfs_crypto_operation_s {
	_myencfs_crypto crypto;
	Aes cipher[1];
	unsigned char *tag;
	size_t tag_size;
};

static
myencfs_error_entry
__error_entry_base(
	const _myencfs_crypto crypto __attribute__((unused)),
	const myencfs_error_entry entry
) {
	return entry;
}

static
myencfs_error_entry
__error_entry_wolfssl_status(
	const int status,
	const myencfs_error_entry entry
) {
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_WOLFSSL_STATUS, (uint32_t)status);
	return entry;
}

_myencfs_crypto
_myencfs_crypto_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	_myencfs_crypto ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_wolfssl", sizeof(*ret))) == NULL) {
		goto cleanup;
	}

	ret->context = context;

cleanup:

	return ret;
}

bool
_myencfs_crypto_construct(
	const _myencfs_crypto crypto
) {
	int status;
	bool ret = false;

	if ((status = wc_InitRng(crypto->rng)) != 0) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			__error_entry_wolfssl_status(
				status,
				_myencfs_error_capture(myencfs_context_get_error(crypto->context))
			),
			"crypto.construct",
			MYENCFS_ERROR_CODE_CRYPTO,
			true,
			"RNG initialization failed"
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_myencfs_crypto_destruct(
	const _myencfs_crypto crypto
) {
	bool ret = true;

	if (crypto != NULL) {
		myencfs_system system = myencfs_context_get_system(crypto->context);
		int status;

		if ((status = wc_FreeRng(crypto->rng)) != 0) {
			_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"crypto.construct",
				MYENCFS_ERROR_CODE_CRYPTO,
				false,
				"RNG initialization failed"
			));
			ret = false;
		}

		if (!myencfs_system_free(system, "_myencfs_crypto_wolfssl", crypto)) {
			ret = false;
		}
	}

	return ret;
}

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto,
	unsigned char * const buf,
	const size_t size
) {
	unsigned char *p = buf;
	size_t s = size;
	int status;
	bool ret = false;

	/*
	 * NOTICE: wc_RNG_GenerateBlock returns partial buffers!!!
	 */
	while (s > 0) {
		if ((status = wc_RNG_GenerateByte(crypto->rng, p)) != 0) {
			_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"wolfssl.rand",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"RNG generate failed"
			));
			goto cleanup;
		}
		p++;
		s--;
	}

	ret = true;

cleanup:

	return ret;
}

_myencfs_crypto_operation
_myencfs_crypto_operation_new(
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(crypto->context);
	_myencfs_crypto_operation ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_operation_wolfssl", sizeof(*ret))) == NULL) {
		goto cleanup;
	}

	ret->crypto = crypto;

cleanup:

	return ret;
}

bool
_myencfs_crypto_operation_construct(
	const _myencfs_crypto_operation op
) {
	int status;
	bool ret = false;

	if (op == NULL) {
		return false;
	}

	if ((status = wc_AesInit(op->cipher, NULL, INVALID_DEVID)) != 0) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			__error_entry_wolfssl_status(
				status,
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
			),
			"wolfssl.init",
			MYENCFS_ERROR_CODE_CRYPTO,
			true,
			"Failed to initialize cipher"
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_myencfs_crypto_operation_destruct(
	const _myencfs_crypto_operation op
) {
	bool ret = true;

	if (op != NULL) {
		myencfs_system system = myencfs_context_get_system(op->crypto->context);

		wc_AesFree(op->cipher);

		if (!myencfs_system_free(system, "_myencfs_crypto_operation_wolfssl", op)) {
			ret = false;
		}
	}

	return ret;
}

size_t
_myencfs_crypto_operation_get_cipher_block_size(
	const _myencfs_crypto_operation op __attribute__((unused))
) {
	return 128/8;
}

size_t
_myencfs_crypto_operation_get_cipher_key_size(
	const _myencfs_crypto_operation op __attribute__((unused))
) {
	return 256/8;
}

size_t
_myencfs_crypto_operation_get_cipher_iv_size(
	const _myencfs_crypto_operation op __attribute__((unused))
) {
	return 96/8;
}

size_t
_myencfs_crypto_operation_get_cipher_tag_size(
	const _myencfs_crypto_operation op __attribute__((unused))
) {
	return 128/8;
}

#if defined(ENABLE_ENCRYPT)

bool
_myencfs_crypto_operation_encrypt_init(
	const _myencfs_crypto_operation op,
	const unsigned char * const key,
	const size_t key_size,
	const unsigned char * const iv,
	const size_t iv_size,
	const unsigned char * const aad,
	const size_t aad_size,
	unsigned char * const tag,
	const size_t tag_size
) {
	int status;
	bool ret = false;

	if (key_size != _myencfs_crypto_operation_get_cipher_key_size(op)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"sanity.keysize",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Key size is invalid expected=%d actual=%d",
				(int)_myencfs_crypto_operation_get_cipher_key_size(op),
				(int)key_size
			)
		));
		goto cleanup;
	}

	op->tag = tag;
	op->tag_size = tag_size;

	if ((status = wc_AesGcmEncryptInit(op->cipher, key, key_size, iv, iv_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.setkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Encryption initialization failed"
			)
		));
		goto cleanup;
	}

	if ((status = wc_AesGcmEncryptUpdate(op->cipher, NULL, NULL, 0, aad, aad_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.set-aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Encryption aad"
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_encrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size __attribute__((unused))
) {
	int status;
	ssize_t ret = -1;

	if (buffer_pt_size > buffer_ct_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"crypto.op.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Plaintext buffer too small"
			)
		));
		goto cleanup;
	}

	if ((status = wc_AesGcmEncryptUpdate(op->cipher, buffer_ct, buffer_pt, buffer_pt_size, NULL, 0)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.encrypt",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Encryption failed"
			)
		));
		goto cleanup;
	}

	ret = buffer_pt_size;	/* BAD! */

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_encrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size __attribute__((unused))
) {
	int status;
	ssize_t ret = -1;

	if ((status = wc_AesGcmEncryptUpdate(op->cipher, buffer_ct, buffer_pt, buffer_pt_size, NULL, 0)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.f.encrypt",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Encryption failed"
			)
		));
		goto cleanup;
	}
	if ((status = wc_AesGcmEncryptFinal(op->cipher, op->tag, op->tag_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.f.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Encryption finalization failed"
			)
		));
		goto cleanup;
	}

	ret = buffer_pt_size;	/* BAD! */

cleanup:

	return ret;
}

#endif

#if defined(ENABLE_DECRYPT)

bool
_myencfs_crypto_operation_decrypt_init(
	const _myencfs_crypto_operation op,
	const unsigned char * const key,
	const size_t key_size,
	const unsigned char * const iv,
	const size_t iv_size,
	const unsigned char * const aad,
	const size_t aad_size,
	const unsigned char * const tag,
	const size_t tag_size
) {
	int status;
	bool ret = false;

	if (key_size != _myencfs_crypto_operation_get_cipher_key_size(op)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"sanity.keysize",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Key size is invalid expected=%d actual=%d",
				(int)_myencfs_crypto_operation_get_cipher_key_size(op),
				(int)key_size
			)
		));
		goto cleanup;
	}

	op->tag = (unsigned char *)tag;
	op->tag_size = tag_size;

	if ((status = wc_AesGcmDecryptInit(op->cipher, key, key_size, iv, iv_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.setkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Decryption initialization failed"
			)
		));
		goto cleanup;
	}

	if ((status = wc_AesGcmDecryptUpdate(op->cipher, NULL, NULL, 0, aad, aad_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.set-aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Decryption aad"
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_decrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_ct,
	const size_t buffer_ct_size,
	unsigned char * const buffer_pt,
	const size_t buffer_pt_size __attribute__((unused))
) {
	int status;
	ssize_t ret = -1;

	if (buffer_ct_size > buffer_pt_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"crypto.op.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Ciphertext buffer too small"
			)
		));
		goto cleanup;
	}

	if ((status = wc_AesGcmDecryptUpdate(op->cipher, buffer_pt, buffer_ct, buffer_ct_size, NULL, 0)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.decrypt",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Decryption failed"
			)
		));
		goto cleanup;
	}

	ret = buffer_ct_size;	/* BAD! */

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_decrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_ct,
	const size_t buffer_ct_size,
	unsigned char * const buffer_pt,
	const size_t buffer_pt_size __attribute__((unused))
) {
	int status;
	ssize_t ret = -1;

	if ((status = wc_AesGcmDecryptUpdate(op->cipher, buffer_pt, buffer_ct, buffer_ct_size, NULL, 0)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.f.decrypt",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Decryption failed"
			)
		));
		goto cleanup;
	}

	if ((status = wc_AesGcmDecryptFinal(op->cipher, op->tag, op->tag_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"wolfssl.f.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Decryption finalization failed"
			)
		));
		goto cleanup;
	}

	ret = buffer_ct_size;	/* BAD! */

cleanup:

	return ret;
}

#endif
