#ifndef __MYENCFS_CRYPTO_H
#define __MYENCFS_CRYPTO_H

#include <myencfs/myencfs-bio.h>
#include <myencfs/myencfs-context.h>

struct __myencfs_crypto_s;
typedef struct __myencfs_crypto_s *_myencfs_crypto;

struct _myencfs_crypto_operation_s;
typedef struct __myencfs_crypto_operation_s *_myencfs_crypto_operation;

_myencfs_crypto
_myencfs_crypto_new(
	const myencfs_context context
);

bool
_myencfs_crypto_construct(
	const _myencfs_crypto crypto
);

bool
_myencfs_crypto_destruct(
	const _myencfs_crypto crypto
);

bool
_myencfs_crypto_rand_bytes(
	const _myencfs_crypto crypto,
	unsigned char * const buf,
	const size_t size
);

_myencfs_crypto_operation
_myencfs_crypto_operation_new(
	const _myencfs_crypto crypto
);

bool
_myencfs_crypto_operation_construct(
	const _myencfs_crypto_operation op
);

bool
_myencfs_crypto_operation_destruct(
	const _myencfs_crypto_operation op
);

size_t
_myencfs_crypto_operation_get_cipher_block_size(
	const _myencfs_crypto_operation op
);

size_t
_myencfs_crypto_operation_get_cipher_key_size(
	const _myencfs_crypto_operation op
);

size_t
_myencfs_crypto_operation_get_cipher_iv_size(
	const _myencfs_crypto_operation op
);

size_t
_myencfs_crypto_operation_get_cipher_tag_size(
	const _myencfs_crypto_operation op
);

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
);

/**
 * receive complete blocks.
 *
 * there are crypto platforms like bcrypt that handle
 * tail only at final.
 */
ssize_t
_myencfs_crypto_operation_encrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size
);

ssize_t
_myencfs_crypto_operation_encrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_pt,
	const size_t buffer_pt_size,
	unsigned char * const buffer_ct,
	const size_t buffer_ct_size
);

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
);

/**
 * receive complete blocks.
 *
 * there are crypto platforms like bcrypt that handle
 * tail only at final.
 */
ssize_t
_myencfs_crypto_operation_decrypt_update(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_ct,
	const size_t buffer_ct_size,
	unsigned char * const buffer_pt,
	const size_t buffer_pt_size
);

ssize_t
_myencfs_crypto_operation_decrypt_final(
	const _myencfs_crypto_operation op,
	const unsigned char * const buffer_ct,
	const size_t buffer_ct_size,
	unsigned char * const buffer_pt,
	const size_t buffer_pt_size
);

#endif
