#ifndef __MYENCFS_BIO_CRYPTO_H
#define __MYENCFS_BIO_CRYPTO_H

#include <stdbool.h>
#include <stdlib.h>

#include "myencfs-bio.h"
#include "myencfs.h"

#ifdef __cplusplus
extern "C" {
#endif

myencfs_bio
myencfs_bio_crypto_encrypt(
	const myencfs myencfs
);

bool
myencfs_bio_crypto_encrypt_init(
	const myencfs_bio bio_enc_pt,
	const myencfs_bio bio_ct,
	const myencfs_bio bio_md,
	const char * const name,
	const size_t pt_size
);

myencfs_bio
myencfs_bio_crypto_decrypt(
	const myencfs myencfs
);

bool
myencfs_bio_crypto_decrypt_init(
	const myencfs_bio bio_dec_pt,
	const myencfs_bio bio_ct,
	const myencfs_bio bio_md,
	const size_t max_size,
	const char * const name
);

#ifdef __cplusplus
}
#endif

#endif
