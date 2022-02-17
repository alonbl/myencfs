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
	const EVP_CIPHER *cipher;
};

struct __myencfs_crypto_operation_s {
	_myencfs_crypto crypto;
	EVP_CIPHER_CTX *ctx;
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

	if ((crypto->cipher = EVP_aes_256_gcm()) == NULL) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(crypto->context)),
			"crypto.algo",
			MYENCFS_ERROR_CODE_DEPENDENCY,
			true,
			"AES-256-GCM is not available"
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

		if (!myencfs_system_free(system, "_myencfs_crypto_openssl", crypto)) {
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
}

_myencfs_crypto_operation
_myencfs_crypto_operation_new(
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(crypto->context);
	_myencfs_crypto_operation ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_operation_openssl", sizeof(*ret))) == NULL) {
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
	bool ret = false;

	if (op == NULL) {
		return false;
	}

	if ((op->ctx = EVP_CIPHER_CTX_new()) == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
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
_myencfs_crypto_operation_destruct(
	const _myencfs_crypto_operation op
) {
	bool ret = true;

	if (op != NULL) {
		myencfs_system system = myencfs_context_get_system(op->crypto->context);

		EVP_CIPHER_CTX_free(op->ctx);

		if (!myencfs_system_free(system, "_myencfs_crypto_operation_openssl", op)) {
			ret = false;
		}
	}

	return ret;
}

size_t
_myencfs_crypto_operation_get_cipher_block_size(
	const _myencfs_crypto_operation op
) {
	return EVP_CIPHER_block_size(op->crypto->cipher);
}

size_t
_myencfs_crypto_operation_get_cipher_key_size(
	const _myencfs_crypto_operation op
) {
	return EVP_CIPHER_key_length(op->crypto->cipher);
}

size_t
_myencfs_crypto_operation_get_cipher_iv_size(
	const _myencfs_crypto_operation op
) {
	return EVP_CIPHER_iv_length(op->crypto->cipher);
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
	int len;
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

	if (EVP_EncryptInit_ex(op->ctx, op->crypto->cipher, NULL, NULL, NULL) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt-init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialize encryption"
			)
		));
		goto cleanup;
	}

	if (EVP_CIPHER_CTX_ctrl(op->ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.iv.size",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set iv size"
			)
		));
		goto cleanup;
	}

	if (EVP_EncryptInit_ex(op->ctx, NULL, NULL, key, iv) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.iv",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set iv"
			)
		));
		goto cleanup;
	}

	if (EVP_EncryptUpdate(op->ctx, NULL, &len, aad, aad_size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.aad",
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
_myencfs_crypto_operation_encrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size
) {
	int len;
	ssize_t ret = -1;

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

	if (EVP_EncryptUpdate(op->ctx, buffer_ct, &len, buffer_pt, buffer_pt_size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to encrypt"
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
	int len;
	ssize_t total = 0;
	ssize_t ret = -1;

	if (buffer_pt_size > buffer_ct_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(op->crypto->context)),
				"crypto.op.f.size",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Ciphertext buffer too small"
			)
		));
		goto cleanup;
	}

	if (EVP_EncryptUpdate(op->ctx, buffer_ct, &len, buffer_pt, buffer_pt_size) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to encrypt"
			)
		));
		goto cleanup;
	}
	total += len;

	if (EVP_EncryptFinal_ex(op->ctx, buffer_ct + total, &len) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to finalize encrypt"
			)
		));
		goto cleanup;
	}
	total += len;

	if (EVP_CIPHER_CTX_ctrl(op->ctx, EVP_CTRL_GCM_GET_TAG, op->tag_size, op->tag) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.tag",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to get tag"
			)
		));
		goto cleanup;
	}

	ret = total;

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
	int len;
	bool ret = false;

	if (key_size != (size_t)EVP_CIPHER_key_length(op->crypto->cipher)) {
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

	if (!EVP_DecryptInit_ex(op->ctx, op->crypto->cipher, NULL, NULL, NULL)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.decrypt-init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialize decryption"
			)
		));
		goto cleanup;
	}

	if (!EVP_CIPHER_CTX_ctrl(op->ctx, EVP_CTRL_GCM_SET_TAG, tag_size, (unsigned char *)tag)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.tag-size",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set tag"
			)
		));
		goto cleanup;
	}

	if (!EVP_CIPHER_CTX_ctrl(op->ctx, EVP_CTRL_GCM_SET_IVLEN, iv_size, NULL)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.iv.size",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set iv size"
			)
		));
		goto cleanup;
	}

	if (!EVP_DecryptInit_ex(op->ctx, NULL, NULL, key, iv)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.decrypt.init",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initialized decryption"
			)
		));
		goto cleanup;
	}

	if (!EVP_DecryptUpdate(op->ctx, NULL, &len, aad, aad_size)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.encrypt.decrypt.aad",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to set aad"
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
	const size_t buffer_pt_size
) {
	int len;
	ssize_t ret = -1;

	if (buffer_ct_size > buffer_pt_size) {
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

	if (!EVP_DecryptUpdate(op->ctx, buffer_pt, &len, buffer_ct, buffer_ct_size)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.decrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to decrypt"
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
	int len;
	ssize_t total = 0;
	ssize_t ret = -1;

	if (buffer_ct_size > buffer_pt_size) {
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

	if (!EVP_DecryptUpdate(op->ctx, buffer_pt, &len, buffer_ct, buffer_ct_size)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.decrypt.f.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to decrypt"
			)
		));
		goto cleanup;
	}
	total += len;

	if (EVP_DecryptFinal_ex(op->ctx, buffer_pt + total, &len) != 1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_openssl_status(
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"openssl.decrypt.f.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to finalize decrypt"
			)
		));
		goto cleanup;
	}

	total += len;

	ret = total;

cleanup:

	return ret;
}

#endif
