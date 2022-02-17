#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <string.h>

#include "myencfs-crypto.h"
#include "myencfs-error-internal.h"
#include "myencfs-util.h"

static struct {
	bool init;
	myencfs_system system;
	void * (*orig_calloc)(size_t, size_t);
	void (*orig_free)(void *);
} __static_context[1];

struct __myencfs_crypto_s {
	myencfs_context context;
	mbedtls_entropy_context entropy[1];
	mbedtls_ctr_drbg_context ctr_drbg[1];
};

struct __myencfs_crypto_cipher_s {
	_myencfs_crypto crypto;
	mbedtls_cipher_context_t cipher[1];
	unsigned char *tag;
	size_t tag_size;
};

#if defined(HAVE_MBEDTLS_PLATFORM_SET_CALLOC_FREE)
static
void *__mbedtls_calloc(size_t nmemb, size_t size) {
	/* TODO: get from TLS */
	if (__static_context->init) {
		return myencfs_system_zalloc(__static_context->system, "mbedtls", nmemb * size);
	} else {
		return calloc(nmemb, size);
	}
}

static
void __mbedtls_free(void *p) {
	/* TODO: get from TLS */
	if (__static_context->init) {
		myencfs_system_free(__static_context->system, "mbedtls", p);
	} else {
		free(p);
	}
}
#endif

void
_myencfs_crypto_mbedtls_static_init(
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
		mbedtls_platform_set_calloc_free(__mbedtls_calloc, __mbedtls_free);
#endif
	}
}

void
_myencfs_crypto_mbedtls_static_clean(
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
__error_entry_mbedtls_status(
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
	bool ret = false;
	int status;

	mbedtls_entropy_init(crypto->entropy);
	mbedtls_ctr_drbg_init(crypto->ctr_drbg);

	if ((status = mbedtls_ctr_drbg_seed(
		crypto->ctr_drbg,
		mbedtls_entropy_func,
		crypto->entropy,
		NULL,
		0
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"mbedtls.seed",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialize random seed"
			)
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

		mbedtls_ctr_drbg_free(crypto->ctr_drbg);
		mbedtls_entropy_free(crypto->entropy);

		if (!myencfs_system_free(system, "_myencfs_crypto_mbed", crypto)) {
			ret = false;
		}
	}

	return ret;
}

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto,
	unsigned char * const _buf,
	const size_t _size
) {
#if defined(ENABLE_RANDOM)
	unsigned char *buf = _buf;
	size_t size = _size;
	int status;
	int ret = false;

	while (size > 0) {
		size_t n = _MYENCFS_UTIL_MIN(MBEDTLS_CTR_DRBG_MAX_REQUEST, size);

		if ((status = mbedtls_ctr_drbg_random(crypto->ctr_drbg, buf, n)) != 0) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				crypto,
				_myencfs_error_entry_base(
					__error_entry_mbedtls_status(
						status,
						_myencfs_error_capture(myencfs_context_get_error(crypto->context))
					),
					"mbedtls.random",
					MYENCFS_ERROR_CODE_CRYPTO,
					true,
					"Failed to generate random"
				)
			));
			goto cleanup;
		}

		buf += n;
		size -= n;
	}

	ret= true;

cleanup:

	return ret;
#else
	(void)crypto;
	(void)_buf;
	(void)_size;
	_myencfs_error_entry_dispatch(__error_entry_base(
		crypto,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(crypto->context)),
			"mbedtls.random",
			MYENCFS_ERROR_CODE_CRYPTO,
			true,
			"Random support is not implemented"
		)
	));
	return false;
#endif
}

_myencfs_crypto_cipher
_myencfs_crypto_cipher_new(
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(crypto->context);
	_myencfs_crypto_cipher cipher = NULL;
	_myencfs_crypto_cipher ret = NULL;

	if ((cipher = myencfs_system_zalloc(system, "_myencfs_crypto_cipher_mbed", sizeof(*cipher))) == NULL) {
		goto cleanup;
	}

	cipher->crypto = crypto;
	mbedtls_cipher_init(cipher->cipher);

	ret = cipher;

cleanup:

	return ret;
}

bool
_myencfs_crypto_cipher_construct(
	const _myencfs_crypto_cipher cipher
) {
	int status;
	bool ret = false;

	if (cipher == NULL) {
		return false;
	}

	if ((status = mbedtls_cipher_setup(
		cipher->cipher,
		mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM)
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.cipher.setup",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to setup cipher"
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_myencfs_crypto_cipher_destruct(
	const _myencfs_crypto_cipher cipher
) {
	bool ret = true;

	if (cipher != NULL) {
		myencfs_system system = myencfs_context_get_system(cipher->crypto->context);

		mbedtls_cipher_free(cipher->cipher);

		ret = myencfs_system_free(system, "_myencfs_crypto_cipher_mbed", cipher) && ret;
	}

	return ret;
}

size_t
_myencfs_crypto_cipher_get_cipher_block_size(
	const _myencfs_crypto_cipher cipher
) {
	return mbedtls_cipher_get_block_size(cipher->cipher);
}

size_t
_myencfs_crypto_cipher_get_cipher_key_size(
	const _myencfs_crypto_cipher cipher
) {
	return mbedtls_cipher_get_key_bitlen(cipher->cipher) / 8;
}

size_t
_myencfs_crypto_cipher_get_cipher_iv_size(
	const _myencfs_crypto_cipher cipher __attribute__((unused))
) {
	return 96/8;
}

size_t
_myencfs_crypto_cipher_get_cipher_tag_size(
	const _myencfs_crypto_cipher cipher __attribute__((unused))
) {
	return 128/8;
}

bool
_myencfs_crypto_cipher_init(
	const _myencfs_crypto_cipher cipher,
	const bool do_encrypt,
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

	if ((status = mbedtls_cipher_reset(cipher->cipher)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.reset",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cipher reset failed"
			)
		));
		goto cleanup;
	}

	if ((status = mbedtls_cipher_setkey(
		cipher->cipher,
		key,
		key_size * 8,
		do_encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.setkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Key import failed"
			)
		));
		goto cleanup;
	}

	if ((status = mbedtls_cipher_set_iv(
		cipher->cipher,
		iv,
		iv_size
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.setiv",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"IV import failed"
			)
		));
		goto cleanup;
	}

	if ((status = mbedtls_cipher_update_ad(
		cipher->cipher,
		aad,
		aad_size
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"AAD update failed"
			)
		));
		goto cleanup;
	}

	cipher->tag = tag;
	cipher->tag_size = tag_size;

	ret = true;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_cipher_update(
	const _myencfs_crypto_cipher cipher,
	const unsigned char * const buffer_in,
	const size_t buffer_in_size,
	unsigned char * const buffer_out,
	const size_t buffer_out_size
) {
	int status;
	size_t len;
	ssize_t ret = -1;


	if (buffer_out_size < buffer_in_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context)),
				"sanity.outsize",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Output size is invalid expected=%d actual=%d",
				(int)buffer_in_size,
				(int)buffer_out_size
			)
		));
		goto cleanup;
	}

	if ((status = mbedtls_cipher_update(
		cipher->cipher,
		buffer_in,
		buffer_in_size,
		buffer_out,
		&len
	)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.encrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to update %s cipher",
				mbedtls_cipher_get_operation(cipher->cipher) == MBEDTLS_ENCRYPT ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	ret = len;

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_cipher_final(
	const _myencfs_crypto_cipher cipher,
	const unsigned char * const buffer_in,
	const size_t buffer_in_size,
	unsigned char * const _buffer_out,
	const size_t _buffer_out_size
) {
	unsigned char * buffer_out = _buffer_out;
	size_t buffer_out_size = _buffer_out_size;
	int status;
	size_t n;
	size_t len = 0;
	ssize_t s;
	ssize_t ret = -1;

	if ((s = _myencfs_crypto_cipher_update(
		cipher,
		buffer_in,
		buffer_in_size,
		buffer_out,
		buffer_out_size
	)) == -1) {
		goto cleanup;
	}
	buffer_out += s;
	/*buffer_out_size -= s;*/
	len += s;

	if ((status = mbedtls_cipher_finish(cipher->cipher, buffer_out, &n)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_mbedtls_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"mbedtls.cipher.finish",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to finalize %s cipher",
				mbedtls_cipher_get_operation(cipher->cipher) == MBEDTLS_ENCRYPT ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}
	n = 0;
	len += n;

	if (mbedtls_cipher_get_operation(cipher->cipher) == MBEDTLS_ENCRYPT) {
		if ((status = mbedtls_cipher_write_tag(
			cipher->cipher,
			cipher->tag,
			cipher->tag_size
		)) != 0) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				cipher->crypto,
				_myencfs_error_entry_base(
					__error_entry_mbedtls_status(
						status,
						_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
					),
					"mbedtls.cipher.tag",
					MYENCFS_ERROR_CODE_CRYPTO,
					true,
					"Failed to extract tag"
				)
			));
			goto cleanup;
		}
	} else {
		if ((status = mbedtls_cipher_check_tag(
			cipher->cipher,
			cipher->tag,
			cipher->tag_size
		)) != 0) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				cipher->crypto,
				_myencfs_error_entry_base(
					__error_entry_mbedtls_status(
						status,
						_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
					),
					"mbedtls.cipher.integ",
					MYENCFS_ERROR_CODE_INTEGRITY,
					true,
					"Integrity check failed"
				)
			));
			goto cleanup;
		}
	}

	ret = len;

cleanup:

	return ret;
}
