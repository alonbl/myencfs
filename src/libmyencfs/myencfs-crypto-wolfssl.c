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

struct __myencfs_crypto_cipher_s {
	_myencfs_crypto crypto;
	bool do_encrypt;
	WOLFSSL_API int (*execute_init)(
		Aes* aes,
		const byte* key,
		word32 len,
		const byte* iv,
		word32 ivSz
	);
	WOLFSSL_API int (*execute_update)(
		Aes* aes,
		byte* out,
		const byte* in,
		word32 sz,
		const byte* authIn,
		word32 authInSz
	);
	WOLFSSL_API int (*execute_final)(
		Aes* aes,
		byte* authTag,
		word32 authTagSz
	);
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

		ret = myencfs_system_free(system, "_myencfs_crypto_wolfssl", crypto) && ret;
	}

	return ret;
}

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto,
	unsigned char * const buf,
	const size_t size
) {
#if defined(ENABLE_RANDOM)
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
#else
	(void)crypto;
	(void)buf;
	(void)size;
	_myencfs_error_entry_dispatch(__error_entry_base(
		crypto,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(crypto->context)),
			"wolfssl.random",
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
	_myencfs_crypto_cipher ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_cipher_wolfssl", sizeof(*ret))) == NULL) {
		goto cleanup;
	}

	ret->crypto = crypto;

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

	if ((status = wc_AesInit(cipher->cipher, NULL, INVALID_DEVID)) != 0) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			__error_entry_wolfssl_status(
				status,
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
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
_myencfs_crypto_cipher_destruct(
	const _myencfs_crypto_cipher cipher
) {
	bool ret = true;

	if (cipher != NULL) {
		myencfs_system system = myencfs_context_get_system(cipher->crypto->context);

		wc_AesFree(cipher->cipher);

		ret = myencfs_system_free(system, "_myencfs_crypto_cipher_wolfssl", cipher) && ret;
	}

	return ret;
}

size_t
_myencfs_crypto_cipher_get_cipher_block_size(
	const _myencfs_crypto_cipher cipher __attribute__((unused))
) {
	return 128/8;
}

size_t
_myencfs_crypto_cipher_get_cipher_key_size(
	const _myencfs_crypto_cipher cipher __attribute__((unused))
) {
	return 256/8;
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

	cipher->do_encrypt = do_encrypt;
	if (cipher->do_encrypt) {
		cipher->execute_init = wc_AesGcmEncryptInit;
		cipher->execute_update = wc_AesGcmEncryptUpdate;
		cipher->execute_final = wc_AesGcmEncryptFinal;
	} else {
		cipher->execute_init = wc_AesGcmDecryptInit;
		cipher->execute_update = wc_AesGcmDecryptUpdate;
		/* Ignore const for tag for simplicity */
		cipher->execute_final = (WOLFSSL_API int (*)(Aes *, byte *, word32))wc_AesGcmDecryptFinal;
	}

	if (key_size != _myencfs_crypto_cipher_get_cipher_key_size(cipher)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context)),
				"sanity.keysize",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Key size is invalid expected=%d actual=%d",
				(int)_myencfs_crypto_cipher_get_cipher_key_size(cipher),
				(int)key_size
			)
		));
		goto cleanup;
	}

	cipher->tag = tag;
	cipher->tag_size = tag_size;

	if ((status = cipher->execute_init(cipher->cipher, key, key_size, iv, iv_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"wolfssl.init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialize %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	if ((status = cipher->execute_update(cipher->cipher, NULL, NULL, 0, aad, aad_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"wolfssl.set-aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to apply aad"
			)
		));
		goto cleanup;
	}

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
	const size_t buffer_out_size __attribute__((unused))
) {
	int status;
	ssize_t ret = -1;

	if (buffer_in_size > buffer_out_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context)),
				"crypto.op.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Input buffer too small"
			)
		));
		goto cleanup;
	}

	if ((status = cipher->execute_update(cipher->cipher, buffer_out, buffer_in, buffer_in_size, NULL, 0)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"wolfssl.encrypt",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to update %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	ret = buffer_in_size;	/* BAD! */

cleanup:

	return ret;
}

ssize_t
_myencfs_crypto_cipher_final(
	const _myencfs_crypto_cipher cipher,
	const unsigned char * const buffer_in,
	const size_t buffer_in_size,
	unsigned char * const buffer_out,
	const size_t buffer_out_size
) {
	int status;
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

	if ((status = cipher->execute_final(cipher->cipher, cipher->tag, cipher->tag_size)) != 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_wolfssl_status(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"wolfssl.f.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to finalize %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	ret = s;

cleanup:

	return ret;
}
