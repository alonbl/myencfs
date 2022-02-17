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

struct __myencfs_crypto_operation_s {
	_myencfs_crypto crypto;
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

		if (!myencfs_system_free(system, "_myencfs_crypto_bcrypt", crypto)) {
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
	NTSTATUS status;
	bool ret = false;

	if ((status =  BCryptGenRandom(
		NULL,
		(BYTE*)&buf,
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
}

_myencfs_crypto_operation
_myencfs_crypto_operation_new(
	const _myencfs_crypto crypto
) {
	myencfs_system system = myencfs_context_get_system(crypto->context);
	_myencfs_crypto_operation ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "_myencfs_crypto_operation_bcrypt", sizeof(*ret))) == NULL) {
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

	return true;
}

bool
_myencfs_crypto_operation_destruct(
	const _myencfs_crypto_operation op
) {
	bool ret = false;

	if (op != NULL) {
		_myencfs_crypto crypto = op->crypto;
		myencfs_system system = myencfs_context_get_system(crypto->context);
		myencfs_error error = myencfs_context_get_error(crypto->context);
		NTSTATUS status;

		if ((status = BCryptDestroyKey(op->hkey)) != STATUS_SUCCESS) {
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

		if (!myencfs_system_free(system, "_myencfs_crypto_operation_bcrypt", op)) {
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
	NTSTATUS status;
	bool ret = false;

	BCRYPT_INIT_AUTH_MODE_INFO(*op->auth_info);
	op->auth_info->pbNonce = (PUCHAR)iv;
	op->auth_info->cbNonce = iv_size;
	op->auth_info->pbAuthData = (PUCHAR)aad;
	op->auth_info->cbAuthData = aad_size;
	op->auth_info->pbTag = (PUCHAR)tag;
	op->auth_info->cbTag = tag_size;
	op->auth_info->pbMacContext = op->mac_context;
	op->auth_info->cbMacContext = sizeof(op->mac_context);
	op->auth_info->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	if ((status = BCryptGenerateSymmetricKey(
		op->crypto->halg,
		&op->hkey,
		0,
		0,
		(PUCHAR)key, key_size,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
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
_myencfs_crypto_operation_encrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size
) {
	NTSTATUS status;
	DWORD bytes_done;
	ssize_t ret = -1;

	if ((status = BCryptEncrypt(
		op->hkey,
		(PUCHAR)buffer_pt, buffer_pt_size,
		op->auth_info,
		op->iv_context, sizeof(op->iv_context),
		buffer_ct, buffer_ct_size,
		&bytes_done,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"bcrypt.encrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed plaintext encryption"
			)
		));
		goto cleanup;
	}

	ret = bytes_done;

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
	NTSTATUS status;
	DWORD bytes_done;
	ssize_t ret = -1;

	op->auth_info->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	if ((status = BCryptEncrypt(
		op->hkey,
		(PUCHAR)buffer_pt, buffer_pt_size,
		op->auth_info,
		op->iv_context, sizeof(op->iv_context),
		buffer_ct, buffer_ct_size,
		&bytes_done,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"bcrypt.encrypt.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Failed finializing plaintext encryption"
			)
		));
		goto cleanup;
	}

	ret = bytes_done;

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
	NTSTATUS status;
	bool ret = false;

	BCRYPT_INIT_AUTH_MODE_INFO(*op->auth_info);
	op->auth_info->pbNonce = (PUCHAR)iv;
	op->auth_info->cbNonce = iv_size;
	op->auth_info->pbAuthData = (PUCHAR)aad;
	op->auth_info->cbAuthData = aad_size;
	op->auth_info->pbTag = (PUCHAR)tag;
	op->auth_info->cbTag = tag_size;
	op->auth_info->pbMacContext = op->mac_context;
	op->auth_info->cbMacContext = sizeof(op->mac_context);
	op->auth_info->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	if ((status = BCryptGenerateSymmetricKey(
		op->crypto->halg,
		&op->hkey,
		0,
		0,
		(PUCHAR)key, key_size,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"bcrypt.genkey",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Key importfailed"
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
	NTSTATUS status;
	DWORD bytes_done;
	ssize_t ret = -1;

	if ((status = BCryptDecrypt(
		op->hkey,
		(PUCHAR)buffer_ct, buffer_ct_size,
		op->auth_info,
		op->iv_context, sizeof(op->iv_context),
		buffer_pt, buffer_pt_size,
		&bytes_done,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"bcrypt.decrypt.update",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot decrypt ciphertext"
			)
		));
		goto cleanup;
	}

	ret = bytes_done;

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
	NTSTATUS status;
	DWORD bytes_done;
	ssize_t ret = -1;

	op->auth_info->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

	if ((status = BCryptDecrypt(
		op->hkey,
		(PUCHAR)buffer_ct, buffer_ct_size,
		op->auth_info,
		op->iv_context, sizeof(op->iv_context),
		buffer_pt, buffer_pt_size,
		&bytes_done,
		0
	)) != STATUS_SUCCESS) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			op->crypto,
			_myencfs_error_entry_base(
				__error_entry_ntstatus(
					status,
					_myencfs_error_capture(myencfs_context_get_error(op->crypto->context))
				),
				"bcrypt.decrypt.final",
				MYENCFS_ERROR_CODE_CRYPTO,
				true,
				"Cannot finilize ciphertext decryption"
			)
		));
		goto cleanup;
	}

	ret = bytes_done;

cleanup:

	return ret;
}

#endif
