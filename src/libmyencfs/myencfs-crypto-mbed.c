#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <string.h>

#include "myencfs-crypto.h"
#include "myencfs-error-internal.h"

static struct {
	bool init;
	myencfs_system system;
	void * (*orig_calloc)(size_t, size_t);
	void (*orig_free)(void *);
} __static_context[1];

struct __myencfs_crypto_s {
	myencfs_context context;
	mbedtls_entropy_context entropy;
};

struct __myencfs_crypto_operation_s {
	_myencfs_crypto crypto;
	mbedtls_gcm_context cipher[1];
	unsigned char *tag;
	size_t tag_size;
};

#if defined(HAVE_MBEDTLS_PLATFORM_SET_CALLOC_FREE)
static
void *__mbed_calloc(size_t nmemb, size_t size) {
	/* TODO: get from TLS */
	if (__static_context->init) {
		return myencfs_system_zalloc(__static_context->system, "mbed", nmemb * size);
	}
	else {
		return calloc(nmemb, size);
	}
}

static
void __mbed_free(void *p) {
	/* TODO: get from TLS */
	if (__static_context->init) {
		myencfs_system_free(__static_context->system, "mbed", p);
	}
	else {
		free(p);
	}
}
#endif

void
_myencfs_crypto_mbed_static_init(
	const myencfs_system system
) {
	if (!__static_context->init) {
		__static_context->init = true;
		__static_context->system = system;
#if 0
		/* Track https://github.com/ARMmbed/mbedtls/pull/5604 */
		mbedtls_platform_get_calloc_free(&__static_context->orig_calloc, &__static_context->orig_free);
#endif
#if defined(HAVE_MBEDTLS_PLATFORM_SET_CALLOC_FREE)
		mbedtls_platform_set_calloc_free(__mbed_calloc, __mbed_free);
#endif
	}
}

void
_myencfs_crypto_mbed_static_clean(
	const myencfs_system system __attribute__((unused))
) {
	if (__static_context->init) {
#if 0
		/* Track https://github.com/ARMmbed/mbedtls/pull/5604 */
		mbedtls_platform_set_calloc_free(__static_context->orig_calloc, __static_context->orig_free);
#endif
		memset(__static_context, 0, sizeof(*__static_context));
	}
}

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
__error_entry_mbed_status(
	const int status,
	const myencfs_error_entry entry
) {
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_MBED_STATUS, (uint32_t)status);
	return entry;
}

_myencfs_crypto
_myencfs_crypto_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	_myencfs_crypto ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_mbed", sizeof(*ret))) == NULL) {
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
	mbedtls_entropy_init(&crypto->entropy);
	return true;
}

bool
_myencfs_crypto_destruct(
	const _myencfs_crypto crypto
) {
	bool ret = true;

	if (crypto != NULL) {
		myencfs_system system = myencfs_context_get_system(crypto->context);

		if (!myencfs_system_free(system, "_myencfs_crypto_mbed", crypto)) {
			ret = false;
		}
	}

	return ret;
}

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto __attribute__((unused)),
	unsigned char * const buf,
	const size_t size
) {
	int status;
	int ret = false;

	if ((status = mbedtls_entropy_func(&crypto->entropy, buf, size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"mbed.random",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to generate random"
			)
		));
		goto cleanup;
	}

	ret= true;

cleanup:

	return ret;
}

_myencfs_crypto_operation
_myencfs_crypto_operation_new(
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(crypto->context);
	_myencfs_crypto_operation ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_operation_mbed", sizeof(*ret))) == NULL) {
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
	if (op == NULL) {
		return false;
	}

	mbedtls_gcm_init(op->cipher);

	return true;
}

bool
_myencfs_crypto_operation_destruct(
	const _myencfs_crypto_operation op
) {
	bool ret = true;

	if (op != NULL) {
		myencfs_system system = myencfs_context_get_system(op->crypto->context);

		mbedtls_gcm_free(op->cipher);

		if (!myencfs_system_free(system, "_myencfs_crypto_operation_mbed", op)) {
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

	if ((status = mbedtls_gcm_setkey(op->cipher, MBEDTLS_CIPHER_ID_AES, key, key_size * 8)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.setkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Key import failed"
			)
		));
		goto cleanup;
	}

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	status = mbedtls_gcm_starts(op->cipher, MBEDTLS_GCM_ENCRYPT, iv, iv_size, aad, aad_size);
#else
	status = mbedtls_gcm_starts(op->cipher, MBEDTLS_GCM_ENCRYPT, iv, iv_size);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.starts",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to init plaintext encryption"
			)
		));
		goto cleanup;
	}

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
	if ((status = mbedtls_gcm_update_ad(op->cipher, aad, aad_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed setting aad"
			)
		));
		goto cleanup;
	}
#endif

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
	const size_t buffer_ct_size
) {
	int status;
	size_t len;
	ssize_t ret = -1;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
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
	status = mbedtls_gcm_update(op->cipher, buffer_pt_size, buffer_pt, buffer_ct);
	len = buffer_pt_size;	/* BAD! */
#else
	status = mbedtls_gcm_update(op->cipher, buffer_pt, buffer_pt_size, buffer_ct, buffer_ct_size, &len);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.encrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed plaintext encryption"
			)
		));
		goto cleanup;
	}

	ret = len;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_encrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size
) {
	int status;
	size_t n;
	size_t len = 0;
	ssize_t ret = -1;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	if (buffer_pt_size > buffer_ct_size) {
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
	status = mbedtls_gcm_update(op->cipher, buffer_pt_size, buffer_pt, buffer_ct);
	n = buffer_pt_size;	/* BAD! */
#else
	status = mbedtls_gcm_update(op->cipher, buffer_pt, buffer_pt_size, buffer_ct, buffer_ct_size, &n);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.encrypt.f.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed plaintext encryption"
			)
		));
		goto cleanup;
	}
	len += n;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	status = mbedtls_gcm_finish(op->cipher, op->tag, op->tag_size);
	n = 0;
#else
	status = mbedtls_gcm_finish(op->cipher, buffer_ct, buffer_ct_size, &n, op->tag, op->tag_size);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.encrypt.finish",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed finializing plaintext encryption"
			)
		));
		goto cleanup;
	}
	len += n;

	ret = len;

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

	if ((status = mbedtls_gcm_setkey(op->cipher, MBEDTLS_CIPHER_ID_AES, key, key_size * 8)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.setkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Key import failed"
			)
		));
		goto cleanup;
	}

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	status = mbedtls_gcm_starts(op->cipher, MBEDTLS_GCM_DECRYPT, iv, iv_size, aad, aad_size);
#else
	status = mbedtls_gcm_starts(op->cipher, MBEDTLS_GCM_DECRYPT, iv, iv_size);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.decrypt.init.start",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to init ciphertext decryption"
			)
		));
		goto cleanup;
	}


#if MBEDTLS_VERSION_NUMBER >= 0x03000000
	if (mbedtls_gcm_update_ad(op->cipher, aad, aad_size) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.decrypt.init.aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set aad"
			)
		));
		goto cleanup;
	}
#endif

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
	const size_t buffer_pt_size
) {
	int status;
	size_t len;
	ssize_t ret = -1;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	if (buffer_pt_size < buffer_ct_size) {
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
	status = mbedtls_gcm_update(op->cipher, buffer_ct_size, buffer_ct, buffer_pt);
	len = buffer_ct_size;	/* BAD! */
#else
	status = mbedtls_gcm_update(op->cipher, buffer_ct, buffer_ct_size, buffer_pt, buffer_pt_size, &len);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.decrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed ciphertext decryption"
			)
		));
		goto cleanup;
	}

	ret = len;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_operation_decrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_ct,
	const size_t buffer_ct_size,
	unsigned char * const buffer_pt,
	const size_t buffer_pt_size
) {
	int status;
	unsigned char tag_actual[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	size_t n;
	size_t len = 0;
	ssize_t ret = -1;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	if (buffer_pt_size < buffer_ct_size) {
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
	status = mbedtls_gcm_update(op->cipher, buffer_ct_size, buffer_ct, buffer_pt);
	n = buffer_ct_size;	/* BAD! */
#else
	status = mbedtls_gcm_update(op->cipher, buffer_ct, buffer_ct_size, buffer_pt, buffer_pt_size, &n);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.decrypt.f.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed ciphertext decryption"
			)
		));
		goto cleanup;
	}
	len += n;

#if MBEDTLS_VERSION_NUMBER < 0x03000000
	status = mbedtls_gcm_finish(op->cipher, tag_actual, op->tag_size);
	n = 0;
#else
	status = mbedtls_gcm_finish(op->cipher, buffer_pt, buffer_pt_size, &n, tag_actual, op->tag_size);
#endif
	if (status != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbed_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"mbed.decrypt.f.finish",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed finializing ciphertext decryption"
			)
		));
		goto cleanup;
	}
	len += n;


	if (memcmp(op->tag, tag_actual, op->tag_size) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"mbed.decrypt.integ",
				MYENCFS_ERROR_CODE_INTEGRITY,
				true,
				"Integrity check failed"
			)
		));
		goto cleanup;
	}

	ret = len;

cleanup:

	return ret;
}

#endif
