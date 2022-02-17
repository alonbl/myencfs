#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include <myencfs/myencfs-bio-file.h>
#include <myencfs/myencfs.h>

#include "getoptutil.h"
#include "util.h"

#include "cmd-decrypt.h"

int
_cmd_info(
	const myencfs myencfs,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_BASE_CT,
		OPT_SUFFIX,
		OPT_NAME
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"base-ct\0DIRECTORY|ciphertext directory base", required_argument, NULL, OPT_BASE_CT},
		{"md-suffix\0STRING|metadata suffix", required_argument, NULL, OPT_SUFFIX},
		{"name\0STRING|ciphertext file name", required_argument, NULL, OPT_NAME},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *name = NULL;
	int have_base_ct = 0;

	myencfs_info info = NULL;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "info [options]", long_options);
				ret = 0;
				goto cleanup;
			case OPT_BASE_CT:
				if (!myencfs_set_base_ct(myencfs, optarg)) {
					goto cleanup;
				}
				have_base_ct = 1;
			break;
			case OPT_SUFFIX:
				if (!myencfs_set_md_suffix(myencfs, optarg)) {
					goto cleanup;
				}
			break;
			case OPT_NAME:
				name = optarg;
			break;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (!have_base_ct) {
		fprintf(stderr, "Ciphertext directory base is mandatory\n");
		goto cleanup;
	}
	if (name == NULL) {
		fprintf(stderr, "File name is mandatory\n");
		goto cleanup;
	}

	if ((info = myencfs_decrypt_info_file(
		myencfs,
		name
	)) == NULL) {
		goto cleanup;
	}

	printf("key-id: %s\n", info->key_id);

	ret = 0;

cleanup:

	myencfs_decrypt_free_info(myencfs, info);

	return ret;
}

int
_cmd_verify(
	const myencfs myencfs,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_KEY_STORE,
		OPT_BASE_CT,
		OPT_SUFFIX,
		OPT_MAX_SIZE,
		OPT_NAME
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"key-store\0DIRECTORY|key store", required_argument, NULL, OPT_KEY_STORE},
		{"base-ct\0DIRECTORY|ciphertext directory base", required_argument, NULL, OPT_BASE_CT},
		{"md-suffix\0STRING|metadata suffix", required_argument, NULL, OPT_SUFFIX},
		{"max-size\0NUMBER|maximum file size", required_argument, NULL, OPT_MAX_SIZE},
		{"name\0STRING|ciphertext file name", required_argument, NULL, OPT_NAME},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *keystore = NULL;
	const char *name = NULL;
	int have_base_ct = 0;
	size_t max_size = _MYENCFS_DEFAULT_MAX_SIZE;

	myencfs_bio bio_dec_pt = NULL;
	myencfs_bio bio_null = NULL;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "verify [options]", long_options);
				ret = 0;
				goto cleanup;
			case OPT_KEY_STORE:
				keystore = optarg;
			break;
			case OPT_BASE_CT:
				if (!myencfs_set_base_ct(myencfs, optarg)) {
					goto cleanup;
				}
				have_base_ct = 1;
			break;
			case OPT_SUFFIX:
				if (!myencfs_set_md_suffix(myencfs, optarg)) {
					goto cleanup;
				}
			break;
			case OPT_MAX_SIZE:
				max_size = atol(optarg);
			break;
			case OPT_NAME:
				name = optarg;
			break;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (keystore == NULL) {
		fprintf(stderr, "Key store is mandatory\n");
		goto cleanup;
	}
	if (!have_base_ct) {
		fprintf(stderr, "Ciphertext directory base is mandatory\n");
		goto cleanup;
	}
	if (name == NULL) {
		fprintf(stderr, "File name is mandatory\n");
		goto cleanup;
	}

	if (!_util_myencfs_set_keystore(myencfs, keystore)) {
		goto cleanup;
	}

	if ((bio_null = myencfs_bio_null(myencfs_get_context(myencfs))) == NULL) {
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_decrypt_bio(
		myencfs,
		max_size,
		name
	)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(myencfs), bio_null, bio_dec_pt, true)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	myencfs_bio_destruct(bio_dec_pt);
	myencfs_bio_destruct(bio_null);

	return ret;
}

int
_cmd_decrypt(
	const myencfs myencfs,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_KEY_STORE,
		OPT_BASE_PT,
		OPT_BASE_CT,
		OPT_SUFFIX,
		OPT_MAX_SIZE,
		OPT_NAME
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"key-store\0DIRECTORY|key store", required_argument, NULL, OPT_KEY_STORE},
		{"base-pt\0DIRECTORY|plaintext directory base", required_argument, NULL, OPT_BASE_PT},
		{"base-ct\0DIRECTORY|ciphertext directory base", required_argument, NULL, OPT_BASE_CT},
		{"md-suffix\0STRING|metadata suffix", required_argument, NULL, OPT_SUFFIX},
		{"max-size\0NUMBER|maximum file size", required_argument, NULL, OPT_MAX_SIZE},
		{"name\0STRING|ciphertext file name", required_argument, NULL, OPT_NAME},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *keystore = NULL;
	const char *name = NULL;
	int have_base_pt = 0;
	int have_base_ct = 0;
	size_t max_size = _MYENCFS_DEFAULT_MAX_SIZE;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "decrypt [options]", long_options);
				ret = 0;
				goto cleanup;
			case OPT_KEY_STORE:
				keystore = optarg;
			break;
			case OPT_BASE_PT:
				if (!myencfs_set_base_pt(myencfs, optarg)) {
					goto cleanup;
				}
				have_base_pt = 1;
			break;
			case OPT_BASE_CT:
				if (!myencfs_set_base_ct(myencfs, optarg)) {
					goto cleanup;
				}
				have_base_ct = 1;
			break;
			case OPT_SUFFIX:
				if (!myencfs_set_md_suffix(myencfs, optarg)) {
					goto cleanup;
				}
			break;
			case OPT_MAX_SIZE:
				max_size = atol(optarg);
			break;
			case OPT_NAME:
				name = optarg;
			break;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (keystore == NULL) {
		fprintf(stderr, "Key store is mandatory\n");
		goto cleanup;
	}
	if (!have_base_pt) {
		fprintf(stderr, "Plaintext directory base is mandatory\n");
		goto cleanup;
	}
	if (!have_base_ct) {
		fprintf(stderr, "Ciphertext directory base is mandatory\n");
		goto cleanup;
	}
	if (name == NULL) {
		fprintf(stderr, "File name is mandatory\n");
		goto cleanup;
	}

	if (!_util_myencfs_set_keystore(myencfs, keystore)) {
		goto cleanup;
	}


	if (!myencfs_decrypt_file(
		myencfs,
		max_size,
		name
	)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}
