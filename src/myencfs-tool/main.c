#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-static.h>
#include <myencfs/myencfs.h>

#include "getoptutil.h"

#if defined(ENABLE_ENCRYPT)
#include "cmd-encrypt.h"
#endif

#if defined(ENABLE_DECRYPT)
#include "cmd-decrypt.h"
#endif

static const char *__FEATURES[] = {
	"sane",
#if defined(ENABLE_ENCRYPT)
	"encrypt",
#endif
#if defined(ENABLE_DECRYPT)
	"decrypt",
#endif
#if defined(ENABLE_BIO_FILE)
	"bio-file",
#endif
	NULL
};

int main(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_VERSION,
		OPT_VERBOSE,
		OPT_MAX
	};

	static struct commands_s {
		const char *c;
		const char *m;
		int (*f)(const myencfs, int argc, char *argv[]);
	} commands[] = {
#if defined(ENABLE_ENCRYPT)
		{"encrypt", "encrypt file", _cmd_encrypt},
#endif
#if defined(ENABLE_DECRYPT)
		{"info", "get file information", _cmd_info},
		{"verify", "verify file", _cmd_verify},
		{"decrypt", "decrypt file", _cmd_decrypt},
#endif
		{NULL, NULL, NULL}
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"version\0print version", no_argument, NULL, OPT_VERSION},
		{"verbose\0verbose diagnostics", no_argument, NULL, OPT_VERBOSE},
		{NULL, 0, NULL, 0}
	};

	struct commands_s *cmd;
	const char *command;
	bool verbose = false;
	char optstring[1024];
	int option;
	int ret = 1;

	myencfs_system system = NULL;
	myencfs_context context = NULL;
	myencfs myencfs = NULL;

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "command [options]", long_options);
				printf("\nAvailable commands:\n");
				for (cmd = commands; cmd->c != NULL; cmd++) {
					printf("%8s%-16s - %s\n", "", cmd->c, cmd->m);
				}
				ret = 0;
				goto cleanup;
			case OPT_VERSION:
				printf("%s-%s (%s)\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUILD_ID);
				printf("Features:");
				{
					const char **p;
					for (p = __FEATURES; *p != NULL; p++) {
						printf(" %s", *p);
					}
				}
				printf("\n");
				ret = 0;
				goto cleanup;
			case OPT_VERBOSE:
				verbose = true;
			break;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Command is missing\n");
		goto cleanup;
	}

	command = argv[optind++];

	if ((system = myencfs_system_new(system)) == NULL) {
		fprintf(stderr, "Cannot create system\n");
		goto cleanup;
	}

	if (!myencfs_system_construct(system)) {
		fprintf(stderr, "Cannot construct system\n");
		goto cleanup;
	}

	if (!myencfs_static_init(system)) {
		fprintf(stderr, "Cannot initialize static context\n");
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
	for (cmd = commands; cmd->c != NULL; cmd++) {
		if (!strcmp(command, cmd->c)) {
			ret = cmd->f(myencfs, argc, argv);
			goto cleanup;
		}
	}

	fprintf(stderr, "Unknown command '%s'\n", command);

cleanup:

	if (system != NULL) {
		myencfs_error error = myencfs_system_get_error(system);

		if (myencfs_error_has_error(error)) {
			char buf[10 * 1024];
			uint32_t code;

			myencfs_error_format_simple(error, &code, buf, sizeof(buf));
			fprintf(stderr, "ERROR: %08x: %s\n", code, buf);

			if (verbose) {
				myencfs_error_format(error, buf, sizeof(buf));
				fputs(buf, stderr);
			}
		}
	}

	myencfs_destruct(myencfs);
	myencfs_context_destruct(context);
	myencfs_static_clean(system);
	myencfs_system_destruct(system);

	return ret;
}
