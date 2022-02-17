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
#include <myencfs/myencfs-system-driver-ids-core.h>
#include <myencfs/myencfs.h>

struct system_userdata {
	bool system_not_allowed;
};

static bool __free(const myencfs_system system, const char * const hint, void * const p) {
	const struct system_userdata *system_userdata = myencfs_system_get_userdata(system);

	if (system_userdata->system_not_allowed) {
		fprintf(stderr, "free (%s) is not allowed\n", hint);
		/*exit(1);*/
	}

	free(p);
	return true;
}
static void *__realloc(const myencfs_system system, const char * const hint __attribute__((unused)), void * const p, size_t size) {
	const struct system_userdata *system_userdata = myencfs_system_get_userdata(system);

	if (system_userdata->system_not_allowed) {
		fprintf(stderr, "realloc (%s) is not allowed\n", hint);
		/*exit(1);*/
	}

	return realloc(p, size);
}

#pragma GCC diagnostic ignored "-Wcast-function-type"
static const struct myencfs_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ MYENCFS_SYSTEM_DRIVER_ID_core_free, (void (*)()) __free},
	{ MYENCFS_SYSTEM_DRIVER_ID_core_realloc, (void (*)()) __realloc},

	{ 0, NULL}
};
#pragma GCC diagnostic pop

static
bool
__key_callback(
	const myencfs myencfs __attribute__((unused)),
	const char * const key_id __attribute__((unused)),
	unsigned char * const key,
	const size_t key_size
) {
	memset(key, 0xaa, key_size);
	return true;
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

	struct system_userdata system_userdata[1];

#define ITER_NUM 100
#define ITER_SIZE (10*1024)
	/* NOTICE: Windows has stack limitation */
	struct {
		struct myentry_s {
			unsigned char plaintext[ITER_SIZE];
			unsigned char ciphertext[ITER_SIZE];
			unsigned char md[MYENCFS_MD_MAX_SIZE];
			size_t md_size;
		} entries[ITER_NUM];
		unsigned char plaintext_scratchpad[ITER_SIZE];
		unsigned char ciphertext_scratchpad[ITER_SIZE];
		unsigned char md_scratchpad[ITER_SIZE];
	} *instance;

	myencfs_bio bio_random = NULL;
	myencfs_bio bio_enc_pt = NULL;
	myencfs_bio bio_dec_pt = NULL;
	myencfs_bio bio_ct = NULL;
	myencfs_bio bio_md = NULL;
	char *name = "file1.dat";
	int ret = 1;
	int i;

	char _myencfs_system[MYENCFS_SYSTEM_CONTEXT_SIZE] = {0};
	myencfs_system system = (myencfs_system)_myencfs_system;
	myencfs_context context = NULL;
	myencfs myencfs = NULL;

	memset(_myencfs_system, 0, sizeof(_myencfs_system));

	memset(system_userdata, 0, sizeof(system_userdata));
	instance = malloc(sizeof(*instance));

	if (!myencfs_system_init(system, sizeof(_myencfs_system))) {
		goto cleanup;
	}

	if (!myencfs_system_construct(system)) {
		goto cleanup;
	}

	if (!myencfs_system_set_userdata(system, system_userdata)) {
		goto cleanup;
	}

	if (!myencfs_system_driver_register(system, __DRIVER_ENTRIES)) {
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

	if ((myencfs = myencfs_new(context)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_construct(myencfs)) {
		goto cleanup;
	}

	if (!myencfs_set_key_callback(myencfs, __key_callback)) {
		goto cleanup;
	}

	if ((bio_random = myencfs_bio_file(context, "/dev/urandom", "rb")) == NULL) {
		goto cleanup;
	}

	if ((bio_enc_pt = myencfs_bio_crypto_encrypt(myencfs)) == NULL) {
		fprintf(stderr, "encrypt alloc failed\n");
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_bio_crypto_decrypt(myencfs)) == NULL) {
		fprintf(stderr, "decrypt alloc failed\n");
		goto cleanup;
	}

	for (i=0;i < ITER_NUM;i++) {
		struct myentry_s *entry = &instance->entries[i];
		if (myencfs_bio_read(
			bio_random,
			entry->plaintext,
			sizeof(entry->plaintext)
		) != sizeof(entry->plaintext)) {
			goto cleanup;
		}
	}

	if ((bio_ct = myencfs_bio_mem_buf(
		context,
		"bio_ct",
		instance->ciphertext_scratchpad,
		0,
		sizeof(instance->ciphertext_scratchpad)
	)) == NULL) {
		goto cleanup;
	}
	if ((bio_md = myencfs_bio_mem_buf(
		context,
		"bio_md",
		instance->md_scratchpad,
		0,
		sizeof(instance->md_scratchpad)
	)) == NULL) {
		goto cleanup;
	}

	system_userdata->system_not_allowed = true;

	for (i=0;i < ITER_NUM;i++) {
		struct myentry_s *entry = &instance->entries[i];
		unsigned char *p;
		ssize_t n;

		myencfs_bio_mem_reset(bio_ct);
		myencfs_bio_mem_reset(bio_md);

		if (!myencfs_bio_crypto_encrypt_init(
			bio_enc_pt,
			bio_ct,
			bio_md,
			name,
			sizeof(entry->plaintext)
		)) {
			fprintf(stderr, "encrypt init failed\n");
			goto cleanup;
		}

		if (myencfs_bio_write(
			bio_enc_pt, entry->plaintext,
			sizeof(entry->plaintext)
		) != sizeof(entry->plaintext)) {
			fprintf(stderr, "encrypt write plaintext failed\n");
			goto cleanup;
		}

		if (myencfs_bio_close(bio_enc_pt) == -1) {
			fprintf(stderr, "encrypt close plaintext failed\n");
			goto cleanup;
		}

		n = myencfs_bio_mem_get_data(bio_ct, (void**)&p);
		if (n != sizeof(entry->plaintext)) {
			fprintf(stderr, "encrypt ct size mismatch\n");
			goto cleanup;
		}
		memcpy(entry->ciphertext, p, n);

		entry->md_size = myencfs_bio_mem_get_data(bio_md, (void**)&p);
		memcpy(entry->md, p, entry->md_size);
	}

	for (i=0;i < ITER_NUM;i++) {
		struct myentry_s *entry = &instance->entries[i];

		myencfs_bio_mem_reset(bio_ct);
		myencfs_bio_mem_reset(bio_md);

		if (myencfs_bio_write(
			bio_ct,
			entry->ciphertext,
			sizeof(entry->ciphertext)
		) != sizeof(entry->ciphertext)) {
			goto cleanup;
		}
		if (myencfs_bio_write(
			bio_md,
			entry->md,
			entry->md_size
		) != (ssize_t)entry->md_size) {
			goto cleanup;
		}

		myencfs_bio_seek(bio_ct, 0, SEEK_SET);
		myencfs_bio_seek(bio_md, 0, SEEK_SET);

		if (!myencfs_bio_crypto_decrypt_init(
			bio_dec_pt,
			bio_ct,
			bio_md,
			1024 * 1024,
			name
		)) {
			fprintf(stderr, "decrypt init failed\n");
			goto cleanup;
		}

		if (myencfs_bio_read(
			bio_dec_pt,
			instance->plaintext_scratchpad,
			sizeof(instance->plaintext_scratchpad)
		) != sizeof(instance->plaintext_scratchpad)) {
			fprintf(stderr, "decrypt pt size mismatch\n");
			goto cleanup;
		}

		if (myencfs_bio_close(bio_dec_pt) == -1) {
			fprintf(stderr, "decrypt close plaintext failed\n");
			goto cleanup;
		}

		if (memcmp(
			instance->plaintext_scratchpad,
			entry->plaintext,
			sizeof(entry->plaintext)
		) != 0) {
			fprintf(stderr, "plaintext mismatch\n");
		}
	}

	system_userdata->system_not_allowed = 0;

	ret = 0;

cleanup:

	__dump_error(system);

	myencfs_bio_destruct(bio_random);
	myencfs_bio_destruct(bio_enc_pt);
	myencfs_bio_destruct(bio_dec_pt);
	myencfs_bio_destruct(bio_ct);
	myencfs_bio_destruct(bio_md);
	myencfs_destruct(myencfs);
	myencfs_context_destruct(context);

	__dump_error(system);

	myencfs_static_clean(system);
	myencfs_system_clean(system, sizeof(_myencfs_system));
	free(instance);

	return ret;
}

#else

int main() {
	exit(77);
}

#endif
