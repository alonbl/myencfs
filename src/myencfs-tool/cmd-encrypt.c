#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include <myencfs/myencfs.h>

#include "getoptutil.h"
#include "util.h"

#include "cmd-encrypt.h"

int
_cmd_encrypt(
	const myencfs myencfs,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_KEY_STORE,
		OPT_KEY_ID,
		OPT_BASE_PT,
		OPT_BASE_CT,
		OPT_SUFFIX,
		OPT_NAME
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"key-store\0DIRECTORY|key store", required_argument, NULL, OPT_KEY_STORE},
		{"key-id\0STRING|key id to use", required_argument, NULL, OPT_KEY_ID},
		{"base-pt\0DIRECTORY|plaintext directory base", required_argument, NULL, OPT_BASE_PT},
		{"base-ct\0DIRECTORY|ciphertext directory base", required_argument, NULL, OPT_BASE_CT},
		{"md-suffix\0STRING|metadata suffix", required_argument, NULL, OPT_SUFFIX},
		{"name\0STRING|plaintext file name", required_argument, NULL, OPT_NAME},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *keystore = NULL;
	const char *name = NULL;
	int have_key_id = 0;
	int have_base_pt = 0;
	int have_base_ct = 0;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "encrypt [options]", long_options);
				ret = 0;
				goto cleanup;
			case OPT_KEY_STORE:
				keystore = optarg;
			break;
			case OPT_KEY_ID:
				if (!myencfs_set_encryption_key_id(myencfs, optarg)) {
					goto cleanup;
				}
				have_key_id = 1;
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
	if (!have_key_id) {
		fprintf(stderr, "Key id is mandatory\n");
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

	if (!myencfs_encrypt_file(
		myencfs,
		name
	)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}
