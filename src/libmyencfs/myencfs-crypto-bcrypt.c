#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <windows.h>

#include <bcrypt.h>
#include <ntstatus.h>

#include "myencfs-crypto.h"
#include "myencfs-error-internal.h"

struct __myencfs_crypto_s {
	myencfs_context context;
	BCRYPT_ALG_HANDLE halg;
};

struct __myencfs_crypto_cipher_s {
	_myencfs_crypto crypto;
	bool do_encrypt;
	BCRYPT_KEY_HANDLE hkey;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info[1];
	unsigned char iv_context[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
	unsigned char mac_context[_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE];
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
__error_entry_ntstatus(
	const NTSTATUS status,
	const myencfs_error_entry entry
) {
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_NTSTATUS, status);
	return entry;
}

_myencfs_crypto
_myencfs_crypto_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	_myencfs_crypto ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_bcrypt", sizeof(*ret))) == NULL) {
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
	NTSTATUS status;
	bool ret = false;

	if ((status = BCryptOpenAlgorithmProvider(&crypto->halg, BCRYPT_AES_ALGORITHM, 0, 0)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"bcrypt.construct",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed open algorithm provider"
			)
		));
		goto cleanup;
	}

	if  ((status = BCryptSetProperty(
		crypto->halg,
		BCRYPT_CHAINING_MODE,
		(BYTE*)BCRYPT_CHAIN_MODE_GCM,
		sizeof(BCRYPT_CHAIN_MODE_GCM), 0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"bcrypt.set-prop",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed setting GCM chain mode"
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
		myencfs_error error = myencfs_context_get_error(crypto->context);
		myencfs_system system = myencfs_context_get_system(crypto->context);
		NTSTATUS status;

		if ((status = BCryptCloseAlgorithmProvider(crypto->halg, 0)) != STATUS_SUCCESS) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				crypto,
				_myencfs_error_entry_base(
					__error_entry_ntstatus(
						status,
						_myencfs_error_capture(error)
					),
					"crypto.destruct.algo",
					MYENCFS_ERROR_CODE_RELEASE,
					false,
					"Failed setting GCM chain mode"
				)
			));
			ret = false;
		}

		ret = myencfs_system_free(system, "_myencfs_crypto_bcrypt", crypto) && ret;
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
	NTSTATUS status;
	bool ret = false;

	if ((status =  BCryptGenRandom(
		NULL,
		(BYTE*)buf,
		size,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(crypto->context))
				),
				"bcrypt.random",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed generating random"
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
			"bcrypt.random",
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

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_cipher_bcrypt", sizeof(*ret))) == NULL) {
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
	if (cipher == NULL) {
		return false;
	}

	return true;
}

bool
_myencfs_crypto_cipher_destruct(
	const _myencfs_crypto_cipher cipher
) {
	bool ret = false;

	if (cipher != NULL) {
		_myencfs_crypto crypto = cipher->crypto;
		myencfs_system system = myencfs_context_get_system(crypto->context);
		myencfs_error error = myencfs_context_get_error(crypto->context);
		NTSTATUS status;

		if ((status = BCryptDestroyKey(cipher->hkey)) != STATUS_SUCCESS) {
			_myencfs_error_entry_dispatch(__error_entry_base(
				crypto,
				_myencfs_error_entry_base(
					__error_entry_ntstatus(
						status,
						_myencfs_error_capture(error)
					),
					"bcrypt.destroy.key",
					MYENCFS_ERROR_CODE_RELEASE,
					false,
					"Cannot destroy key"
				)
			));
			ret = false;
		}

		ret = myencfs_system_free(system, "_myencfs_crypto_cipher_bcrypt", cipher) && ret;
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
	NTSTATUS status;
	bool ret = false;

	cipher->do_encrypt = do_encrypt;

	BCRYPT_INIT_AUTH_MODE_INFO(*cipher->auth_info);
	cipher->auth_info->pbNonce = (PUCHAR)iv;
	cipher->auth_info->cbNonce = iv_size;
	cipher->auth_info->pbAuthData = (PUCHAR)aad;
	cipher->auth_info->cbAuthData = aad_size;
	cipher->auth_info->pbTag = (PUCHAR)tag;
	cipher->auth_info->cbTag = tag_size;
	cipher->auth_info->pbMacContext = cipher->mac_context;
	cipher->auth_info->cbMacContext = sizeof(cipher->mac_context);
	cipher->auth_info->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	if ((status = BCryptGenerateSymmetricKey(
		cipher->crypto->halg,
		&cipher->hkey,
		0,
		0,
		(PUCHAR)key, key_size,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"bcrypt.genkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Key import failed"
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
	NTSTATUS status;
	DWORD bytes_done;
	ssize_t ret = -1;

	if ((status = (cipher->do_encrypt ? BCryptEncrypt : BCryptDecrypt)(
		cipher->hkey,
		(PUCHAR)buffer_in, buffer_in_size,
		cipher->auth_info,
		cipher->iv_context, sizeof(cipher->iv_context),
		buffer_out, buffer_out_size,
		&bytes_done,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			cipher->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(cipher->crypto->context))
				),
				"bcrypt.cipher.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed to update %s cipher",
				cipher->do_encrypt ? "encryption" : "decryption"
			)
		));
		goto cleanup;
	}

	ret = bytes_done;

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
	cipher->auth_info->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	return _myencfs_crypto_cipher_update(
		cipher,
		buffer_in,
		buffer_in_size,
		buffer_out,
		buffer_out_size
	);
}
