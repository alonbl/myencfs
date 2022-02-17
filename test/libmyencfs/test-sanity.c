#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ENABLE_ENCRYPT) && defined(ENABLE_DECRYPT) && defined(ENABLE_BIO_FILE)

#include <myencfs/myencfs-bio-crypto.h>
#include <myencfs/myencfs-bio-file.h>
#include <myencfs/myencfs-static.h>
#include <myencfs/myencfs.h>

struct __keystore {
	char *key_id;
	unsigned char key[256/8];
};

static
bool
__key_callback(
	const myencfs myencfs,
	const char * const key_id __attribute__((unused)),
	unsigned char * const key,
	const size_t key_size
) {
	struct __keystore *keystore = (struct __keystore *)myencfs_context_get_user_context(myencfs_get_context(myencfs));
	bool ret = false;

	if (strcmp(key_id, keystore->key_id)) {
		fprintf(stderr, "Incorrect key id expected='%s' actual='%s'\n", keystore->key_id, key_id);
		goto cleanup;
	}

	if (key_size != sizeof(keystore->key)) {
		fprintf(stderr, "Incorrect key size expected=%ld actual=%ld\n", (long)sizeof(keystore), (long)key_size);
		goto cleanup;
	}

	memcpy(key, keystore->key, key_size);

	ret = true;

cleanup:

	return ret;
}

static
void
__dump_error(
	const myencfs_system system
) {
	if (system != NULL) {
		myencfs_error error = myencfs_system_get_error(system);

		if (myencfs_error_has_error(error)) {
			char buf[2048];
			myencfs_error_format(error, buf, sizeof(buf));
			fputs(buf, stderr);
		}
		myencfs_error_reset(error);
	}
}

int main() {

#define KEY_ID "keyid1"
	struct __keystore keystore[1];
	unsigned char plaintext1[123217];
	myencfs_bio bio_random = NULL;
	myencfs_bio bio_pt1 = NULL;
	myencfs_bio bio_enc_pt1 = NULL;
	myencfs_bio bio_pt2 = NULL;
	myencfs_bio bio_dec_pt2 = NULL;
	myencfs_bio bio_ct = NULL;
	myencfs_bio bio_md = NULL;
	char *name = "file1.dat";
	int ret = 1;

	myencfs_system system = NULL;
	myencfs_context context = NULL;
	myencfs myencfs = NULL;

	memset(keystore, 0, sizeof(keystore));

	if ((system = myencfs_system_new()) == NULL) {
		goto cleanup;
	}

	if (!myencfs_system_construct(system)) {
		goto cleanup;
	}

	if (!myencfs_static_init(system)) {
		goto cleanup;
	}

	if ((context = myencfs_context_new(system)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_context_construct(context)) {
		goto cleanup;
	}

	if (!myencfs_context_set_user_context(context, keystore)) {
		goto cleanup;
	}

	if ((bio_random = myencfs_bio_file(context, "/dev/urandom", "rb")) == NULL) {
		goto cleanup;
	}

	keystore->key_id = KEY_ID;
	if (myencfs_bio_read(
		bio_random,
		keystore->key,
		sizeof(keystore->key)
	) != sizeof(keystore->key)) {
		goto cleanup;
	}

	if (myencfs_bio_read(
		bio_random,
		plaintext1,
		sizeof(plaintext1)
	) != sizeof(plaintext1)) {
		goto cleanup;
	}

	if ((myencfs = myencfs_new(context)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_construct(myencfs)) {
		goto cleanup;
	}

	if (!myencfs_set_encryption_key_id(myencfs, KEY_ID)) {
		goto cleanup;
	}

	if (!myencfs_set_key_callback(myencfs, __key_callback)) {
		goto cleanup;
	}

	if ((bio_pt1 = myencfs_bio_mem_buf(
		context,
		"bio_pt1",
		plaintext1,
		sizeof(plaintext1),
		sizeof(plaintext1))
	) == NULL) {
		goto cleanup;
	}
	if ((bio_ct = myencfs_bio_mem(context, "bio_ct")) == NULL) {
		goto cleanup;
	}
	if ((bio_md = myencfs_bio_mem(context, "bio_md")) == NULL) {
		goto cleanup;
	}

	if ((bio_enc_pt1 = myencfs_bio_crypto_encrypt(myencfs)) == NULL) {
		fprintf(stderr, "encrypt alloc failed\n");
		goto cleanup;
	}

	if (!myencfs_bio_crypto_encrypt_init(
		bio_enc_pt1,
		bio_ct,
		bio_md,
		name,
		sizeof(plaintext1)
	)) {
		fprintf(stderr, "encrypt init failed\n");
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(myencfs), bio_enc_pt1, bio_pt1, true)) {
		fprintf(stderr, "encrypt failed\n");
		goto cleanup;
	}

	if (myencfs_bio_tell(bio_ct) < (ssize_t)sizeof(plaintext1)) {
		fprintf(stderr, "ciphertext size is bad\n");
		goto cleanup;
	}

	{
		unsigned char *p;
		myencfs_bio_mem_get_data(bio_ct, (void**)&p);
		if (memcmp(p, plaintext1, sizeof(plaintext1)) == 0) {
			fprintf(stderr, "plaintext and ciphertext are equal\n");
			goto cleanup;
		}
	}

	if ((bio_pt2 = myencfs_bio_mem(context, "bio_pt2")) == NULL) {
		goto cleanup;
	}
	if (myencfs_bio_seek(bio_ct, 0, SEEK_SET) == -1) {
		goto cleanup;
	}
	if (myencfs_bio_seek(bio_md, 0, SEEK_SET) == -1) {
		goto cleanup;
	}

	if ((bio_dec_pt2 = myencfs_bio_crypto_decrypt(myencfs)) == NULL) {
		fprintf(stderr, "decrypt alloc failed\n");
		goto cleanup;
	}

	if (!myencfs_bio_crypto_decrypt_init(
		bio_dec_pt2,
		bio_ct,
		bio_md,
		1024 * 1024,
		name
	)) {
		fprintf(stderr, "decrypt init failed\n");
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(myencfs), bio_pt2, bio_dec_pt2, true)) {
		fprintf(stderr, "decrypt failed\n");
		goto cleanup;
	}

	{
		unsigned char *p;
		size_t s;
		s = myencfs_bio_mem_get_data(bio_pt2, (void**)&p);

		if (s != sizeof(plaintext1)) {
			fprintf(stderr, "plaintext2 size is bad expected=%ld actual=%ld\n", (long)sizeof(plaintext1), (long)s);
			goto cleanup;
		}

		if (memcmp(p, plaintext1, sizeof(plaintext1)) != 0) {
			fprintf(stderr, "plaintext1 and plaintext2 differ\n");
			goto cleanup;
		}
	}

	ret = 0;

cleanup:

	__dump_error(system);

	myencfs_bio_destruct(bio_random);
	myencfs_bio_destruct(bio_pt1);
	myencfs_bio_destruct(bio_enc_pt1);
	myencfs_bio_destruct(bio_pt2);
	myencfs_bio_destruct(bio_dec_pt2);
	myencfs_bio_destruct(bio_ct);
	myencfs_bio_destruct(bio_md);
	myencfs_destruct(myencfs);
	myencfs_context_destruct(context);
	myencfs_static_clean(system);

	__dump_error(system);

	myencfs_system_destruct(system);

	return ret;
}

#else

int main() {
	exit(77);
}

#endif
