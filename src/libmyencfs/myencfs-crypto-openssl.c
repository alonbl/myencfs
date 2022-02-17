#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "myencfs-crypto.h"
#include "myencfs-error-internal.h"

static struct {
        bool init;
        myencfs_system system;
        void *(*orig_m)(size_t, const char *, int);
        void *(*orig_r)(void *, size_t, const char *, int);
        void (*orig_f)(void *, const char *, int);
} __static_context[1];

struct __myencfs_crypto_s {
	myencfs_context context;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
	OSSL_LIB_CTX *lctx;
#endif
	const EVP_CIPHER *evp;
};

struct __myencfs_crypto_cipher_s {
	_myencfs_crypto crypto;
	EVP_CIPHER_CTX *ctx;
	bool do_encrypt;
	unsigned char *tag;
	size_t tag_size;
};

static
void *
__openssl_malloc(
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	/* TODO: get from TLS */
	return myencfs_system_realloc(__static_context->system, "openssl", NULL, num);
}

static
void *
__openssl_realloc(
	void *p,
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	/* TODO: get from TLS */
	return myencfs_system_realloc(__static_context->system, "openssl", p, num);
}

static
void
__openssl_free(
	void *p,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	/* TODO: get from TLS */
	myencfs_system_free(__static_context->system, "openssl", p);
}

void
_myencfs_crypto_openssl_static_init(
	const myencfs_system system
) {
	if (!__static_context->init) {
		__static_context->init = true;
		__static_context->system = system;
		CRYPTO_get_mem_functions(
			&__static_context->orig_m,
			&__static_context->orig_r,
			&__static_context->orig_f
		);
		if (!CRYPTO_set_mem_functions(
			__openssl_malloc,
			__openssl_realloc,
			__openssl_free
		)) {
			/* can we do anything? */
		}
	}
}

void
_myencfs_crypto_openssl_static_clean(
	const myencfs_system system __attribute__((unused))
) {
	if (__static_context->init) {
		CRYPTO_set_mem_functions(
			__static_context->orig_m,
			__static_context->orig_r,
			__static_context->orig_f
		);
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

#define __OPENSSL_MSG_SIZE 1024

static
int
__error_entry_openssl_status_cb(
	const char *str,
	size_t len __attribute__((unused)),
	void *u
) {
	char *buf = (char *)u;
	size_t s = strlen(buf);

	buf += s;
	s = __OPENSSL_MSG_SIZE - s;

	strncpy(buf, str, s-1);
	buf[s-1] = '\x0';

	return 1;
}

static
myencfs_error_entry
__error_entry_openssl_status(
	const myencfs_error_entry entry
) {
	char buf[__OPENSSL_MSG_SIZE];

	memset(buf, 0, sizeof(buf));
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_OPENSSL_STATUS, ERR_peek_last_error());
	ERR_print_errors_cb(__error_entry_openssl_status_cb, buf);
	_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_OPENSSL_STATUS_STR, buf);
	return entry;
}

_myencfs_crypto
_myencfs_crypto_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	_myencfs_crypto ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_openssl", sizeof(*ret))) == NULL) {
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

	if (OPENSSL_init_crypto(
		(
			OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
			OPENSSL_INIT_NO_ADD_ALL_CIPHERS |
			OPENSSL_INIT_NO_ADD_ALL_DIGESTS |
			0
		),
		NULL
	) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(crypto->context)),
				"openssl.init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot init openssl library"
			)
		));
		goto cleanup;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000
	crypto->evp = EVP_aes_256_gcm();
#else
	if ((crypto->lctx = OSSL_LIB_CTX_new()) == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"openssl.OSSL_LIB_CTX_new",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot create openssl library context"
			)
		));
		goto cleanup;
	}

	crypto->evp = EVP_CIPHER_fetch(crypto->lctx, "AES-256-GCM", NULL);
#endif
	if (crypto->evp == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"openssl.CTX_fetch",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot fetch cipher context"
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000
		/* We know what we are doing... */
		EVP_CIPHER_free((EVP_CIPHER *)crypto->evp);
		OSSL_LIB_CTX_free(crypto->lctx);
#endif
		OPENSSL_cleanup();

		ret = myencfs_system_free(system, "_myencfs_crypto_openssl", crypto) && ret;
	}

	return ret;
}

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto __attribute__((unused)),
	unsigned char * const buf,
	const size_t size
) {
#if defined(ENABLE_RANDOM)
	bool ret = false;

	if (RAND_bytes(buf, size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"openssl.random",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to generate random"
			)
		));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
#else
	(void)buf;
	(void)size;
	_myencfs_error_entry_dispatch(__error_entry_base(
		crypto,
		_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(crypto->context)),
			"openssl.random",
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

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_cipher_openssl", sizeof(*ret))) == NULL) {
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
	bool ret = false;

	if (cipher == NULL) {
		return false;
	}

	if ((cipher->ctx = EVP_CIPHER_CTX_new()) == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.CTX_new",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot create cipher context"
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

		EVP_CIPHER_CTX_free(cipher->ctx);

		ret = myencfs_system_free(system, "_myencfs_crypto_cipher_openssl", cipher) && ret;
	}

	return ret;
}

size_t
_myencfs_crypto_cipher_get_cipher_block_size(
	const _myencfs_crypto_cipher cipher
) {
	return EVP_CIPHER_block_size(cipher->crypto->evp);
}

size_t
_myencfs_crypto_cipher_get_cipher_key_size(
	const _myencfs_crypto_cipher cipher
) {
	return EVP_CIPHER_key_length(cipher->crypto->evp);
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
	int len;
	bool ret = false;

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

	cipher->do_encrypt = do_encrypt;

	if (EVP_CipherInit_ex(cipher->ctx, cipher->crypto->evp, NULL, NULL, NULL, cipher->do_encrypt ? 1 : 0) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher-init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialize %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	if (cipher->do_encrypt) {
		cipher->tag = tag;
		cipher->tag_size = tag_size;
	} else {
		if (!EVP_CIPHER_CTX_ctrl(cipher->ctx, EVP_CTRL_GCM_SET_TAG, tag_size, (unsigned char *)tag)) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				cipher->crypto,
				_myencfs_error_entry_base(
					__error_entry_openssl_status(
						_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
					),
					"openssl.set.tag",
					MYENCFS_ERROR_CODE_CRYPTO,
					true,
					"Failed to set tag"
				)
			));
			goto cleanup;
		}
	}

	if (EVP_CIPHER_CTX_ctrl(cipher->ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher.iv.size",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set iv size"
			)
		));
		goto cleanup;
	}

	if (EVP_CipherInit_ex(cipher->ctx, NULL, NULL, key, iv, -1) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher.iv",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set iv"
			)
		));
		goto cleanup;
	}

	len = 0;
	if (EVP_CipherUpdate(cipher->ctx, NULL, &len, aad, aad_size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher.aad",
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
	const size_t buffer_out_size
) {
	int len;
	ssize_t ret = -1;

	if (buffer_in_size > buffer_out_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context)),
				"crypto.cipher.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Output buffer too small"
			)
		));
		goto cleanup;
	}

	len = 0;
	if (EVP_CipherUpdate(cipher->ctx, buffer_out, &len, buffer_in, buffer_in_size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to update %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
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
	unsigned char * const buffer_out,
	const size_t buffer_out_size
) {
	int len;
	ssize_t total = 0;
	ssize_t ret = -1;
	ssize_t s;

	if ((s = _myencfs_crypto_cipher_update(
		cipher,
		buffer_in,
		buffer_in_size,
		buffer_out,
		buffer_out_size
	)) == -1) {
		goto cleanup;
	}
	total += s;

	if (buffer_out_size - total < _myencfs_crypto_cipher_get_cipher_block_size(cipher)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context)),
				"crypto.cipher.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Output buffer too small"
			)
		));
		goto cleanup;
	}

	len = 0;
	if (EVP_CipherFinal_ex(cipher->ctx, buffer_out + total, &len) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"openssl.cipher.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to finalize %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}
	total += len;

	if (cipher->do_encrypt) {
		if (EVP_CIPHER_CTX_ctrl(cipher->ctx, EVP_CTRL_GCM_GET_TAG, cipher->tag_size, cipher->tag) != 1) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				cipher->crypto,
				_myencfs_error_entry_base(
					__error_entry_openssl_status(
						_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
					),
					"openssl.cipher.get-tag",
					MYENCFS_ERROR_CODE_CRYPTO,
					true,
					"Failed to get tag"
				)
			));
			goto cleanup;
		}
	}

	ret = total;

cleanup:

	return ret;
}
