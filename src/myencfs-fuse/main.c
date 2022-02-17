#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <myencfs/myencfs-bio-file.h>
#include <myencfs/myencfs-error.h>
#include <myencfs/myencfs.h>

struct myencfs_fuse_private {
	struct options {
		int log_level;
		const char *log_file;
		const char *key_store;
		const char *base;
		const char *md_suffix;
		size_t max_size;
		int show_help;
	} options[1];

	FILE *fp_log;
	myencfs_context context;
	myencfs myencfs;
};

static
inline
const struct myencfs_fuse_private *
__get_private(void) {
	return (struct myencfs_fuse_private *)fuse_get_context()->private_data;
}

static
int
__fuse_getattr(
	const char *path, struct stat *stbuf,
	struct fuse_file_info *fi __attribute__((unused))
) {
	const struct myencfs_fuse_private *private = __get_private();
	struct stat stat1;
	char name[PATH_MAX];
	int ret = -ENOENT;

	memset(stbuf, 0, sizeof(struct stat));

	snprintf(name, sizeof(name), "%s%s", private->options->base, path);
	if (stat(name, &stat1) == -1) {
		ret = -errno;
		goto cleanup;
	}

	if ((stat1.st_mode & S_IFDIR) != 0) {
		stbuf->st_mode = S_IFDIR | (stat1.st_mode & 0555);
		stbuf->st_nlink = 2;
	} else if ((stat1.st_mode & S_IFREG) != 0) {
		stbuf->st_mode = S_IFREG | (stat1.st_mode & 0444);
		stbuf->st_nlink = 1;
		stbuf->st_size = stat1.st_size;	/* maybe few bytes more */
	} else {
		fuse_log(
			FUSE_LOG_DEBUG,
			"getattr '%s' failed unsupported attributes %08o\n",
			path,
			stat1.st_mode
		);
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}

static
int
__fuse_readdir(
	const char *path,
	void *buf,
	fuse_fill_dir_t filler,
	off_t offset __attribute__((unused)),
	struct fuse_file_info *fi __attribute__((unused)),
	enum fuse_readdir_flags flags __attribute__((unused))
) {
	const struct myencfs_fuse_private *private = __get_private();
	const char *suffix = myencfs_get_md_suffix(private->myencfs);
	char dir[PATH_MAX];
	DIR *d = NULL;
	struct dirent *entry;
	int ret = -ENOENT;

	snprintf(dir, sizeof(dir), "%s%s", private->options->base, path);

	if ((d = opendir(dir)) == NULL) {
		ret = -ENOENT;
		fuse_log(FUSE_LOG_DEBUG, "opendir '%s' failed\n", private->options->base);
		goto cleanup;
	}

	while ((entry = readdir(d)) != NULL) {

		char name[PATH_MAX];
		struct stat stat1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
		snprintf(name, sizeof(name), "%s/%s", dir, entry->d_name);
#pragma GCC diagnostic pop
		if (stat(name, &stat1) == -1) {
			goto cleanup;
		}


		if ((stat1.st_mode & S_IFDIR) != 0) {
			fuse_log(FUSE_LOG_DEBUG, "readdir filling directory '%s'\n", name);
			filler(
				buf,
				entry->d_name,
				NULL,
				0,
				0
			);
		}
		else if ((stat1.st_mode & S_IFREG) != 0) {
			char md[PATH_MAX];

			snprintf(md, sizeof(md), "%s%s", name, suffix);
			if (access(md, F_OK) == -1) {
				fuse_log(FUSE_LOG_DEBUG, "readdir skipping '%s' name as no metadata\n", name);
			} else {
				fuse_log(FUSE_LOG_DEBUG, "readdir filling '%s'\n", entry->d_name);
				filler(
					buf,
					entry->d_name,
					NULL,
					0,
					0
				);
			}
		} else {
			fuse_log(
				FUSE_LOG_DEBUG,
				"readdir '%s' ignored unsupported attributes %08o\n",
				name,
				stat1.st_mode
			);
		}

	}

	ret = 0;

cleanup:

	if (d != NULL) {
		closedir(d);
	}

	return ret;
}

static
int
__fuse_open(
	const char *path,
	struct fuse_file_info *fi
) {
	const struct myencfs_fuse_private *private = __get_private();
	myencfs_bio bio_pt = NULL;
	myencfs_bio bio_dec_pt = NULL;
	int ret = -ENOENT;

	if ((fi->flags & O_ACCMODE) != O_RDONLY) {
		ret = -EACCES;
		fuse_log(FUSE_LOG_DEBUG, "open request is not read only\n");
		goto cleanup;
	}

	if ((bio_pt = myencfs_bio_mem(myencfs_get_context(private->myencfs), path)) == NULL) {
		ret = -ENOMEM;
		fuse_log(FUSE_LOG_DEBUG, "failed to allocate bio\n");
		goto cleanup;
	}

	if ((bio_dec_pt = myencfs_decrypt_bio(
		private->myencfs,
		private->options->max_size,
		path + 1 /* remove leading slash */
	)) == NULL) {
		ret = -EPERM;
		fuse_log(FUSE_LOG_ERR, "Cannot init decrypt '%s'\n", path);
		goto cleanup;
	}

	if (!myencfs_bio_copy(myencfs_get_context(private->myencfs), bio_pt, bio_dec_pt, true)) {
		ret = -EPERM;
		fuse_log(FUSE_LOG_ERR, "Cannot decrypt '%s'\n", path);
		goto cleanup;
	}

	fi->fh = (uint64_t)bio_pt;
	bio_pt = NULL;
	ret = 0;

cleanup:

	if (myencfs_error_has_error(myencfs_context_get_error(private->context))) {
		char buf[10 * 1024];
		myencfs_error_format(myencfs_context_get_error(private->context), buf, sizeof(buf));
		fuse_log(FUSE_LOG_ERR, "myencfs error:\n%s", buf);
		myencfs_context_error_reset(private->context);
	}

	myencfs_bio_destruct(bio_pt);
	myencfs_bio_destruct(bio_dec_pt);

	return ret;
}

static
int
__fuse_read(
	const char *path __attribute__((unused)),
	char *buf,
	size_t size,
	off_t offset,
	struct fuse_file_info *fi
) {
	myencfs_bio bio = (myencfs_bio)fi->fh;
	unsigned char *bio_p;
	size_t bio_s;
	size_t s;

	bio_s = myencfs_bio_mem_get_data(bio, (void **)&bio_p);

	if ((size_t)offset > bio_s) {
		s = 0;
	} else if (offset + size > bio_s) {
		s = bio_s - offset;
	} else {
		s = size;
	}

	if (s > 0) {
		memcpy(buf, (char *)bio_p + offset, s);
	}
	return s;
}


static
int
__fuse_release(
	const char *path __attribute__((unused)),
	struct fuse_file_info *fi
) {
	myencfs_bio bio = (myencfs_bio)fi->fh;
	unsigned char *p;
	size_t s;
	s = myencfs_bio_mem_get_data(bio, (void **)&p);
	memset(p, 0, s);
	myencfs_bio_destruct(bio);
	fi->fh = 0l;
	return 0;
}

static const struct fuse_operations __fuse_oper = {
	.getattr	= __fuse_getattr,
	.readdir	= __fuse_readdir,
	.open		= __fuse_open,
	.read		= __fuse_read,
	.release	= __fuse_release,
};

static
void
__fuse_log(
	enum fuse_log_level level,
	const char *fmt,
	va_list ap
) {
	struct fuse_context *context = fuse_get_context();
	const char *levelstr = NULL;
	FILE *log = stderr;

	if (context != NULL) {
		const struct myencfs_fuse_private *private = (struct myencfs_fuse_private *)context->private_data;

		if (private != NULL) {
			log = private->fp_log;

			if ((int)level > private->options->log_level) {
				goto cleanup;
			}
		}
	}

	switch (level) {
		default:
			levelstr = "XXX ";
		break;
		case FUSE_LOG_EMERG:
			levelstr = "EMR ";
		break;
		case FUSE_LOG_ALERT:
			levelstr = "ALR ";
		break;
		case FUSE_LOG_CRIT:
			levelstr = "CRT ";
		break;
		case FUSE_LOG_ERR:
			levelstr = "ERR ";
		break;
		case FUSE_LOG_WARNING:
			levelstr = "WRN ";
		break;
		case FUSE_LOG_NOTICE:
			levelstr = "NTC ";
		break;
		case FUSE_LOG_INFO:
			levelstr = "INF ";
		break;
		case FUSE_LOG_DEBUG:
			levelstr = "DBG ";
		break;
	}
	fputs(levelstr, log);
	vfprintf(log, fmt, ap);
	fflush(log);

cleanup:

	return;
}

static
bool
__key_callback(
	const myencfs myencfs,
	const char * const key_id __attribute__((unused)),
	unsigned char * const key,
	const size_t key_size
) {
	const char *keystore = ((struct myencfs_fuse_private *)myencfs_context_get_user_context(myencfs_get_context(myencfs)))->options->key_store;
	char *path = NULL;
	FILE *fp = NULL;
	bool ret = false;

	if (key_id == NULL) {
		goto cleanup;
	}

	if ((path = malloc(strlen(keystore) + strlen(key_id) + 2)) == NULL) {
		goto cleanup;
	}

	sprintf(path, "%s/%s", keystore, key_id);

	if ((fp = fopen(path, "rb")) == NULL) {
		fuse_log(FUSE_LOG_WARNING, "Key id '%s' is not available", key_id);
		goto cleanup;
	}

	if (fread(key, key_size, 1, fp) != 1) {
		fuse_log(FUSE_LOG_WARNING, "Cannot read keyid '%s'", key_id);
		goto cleanup;
	}

	ret = true;

cleanup:

	if (fp != NULL) {
		fclose(fp);
	}

	free(path);

	return ret;
}

static
void
__show_help(void)
{
	printf(
		"\n"
		"Options for myencfs-fuse:\n"
		"    --log-level=N          log level (0-7)\n"
		"    --log-file=FILE        log file\n"
		"    --key-store=DIR        location of key store\n"
		"    --base=DIR             location of ciphertext directory\n"
		"    --md-suffix=SUFFIX     metadata suffix\n"
		"    --max-size=N           maximum file size, default 1M\n"
		"\n"
	);
}

int main(int argc, char *argv[])
{
#define OPTION(t, p)                           \
	{ t, offsetof(struct options, p), 1 }

	static const struct fuse_opt option_spec[] = {
		OPTION("--log-level=%d", log_level),
		OPTION("--log-file=%s", log_file),
		OPTION("--key-store=%s", key_store),
		OPTION("--base=%s", base),
		OPTION("--md-suffix=%s", md_suffix),
		OPTION("--max-size=%ld", max_size),
		OPTION("-h", show_help),
		OPTION("--help", show_help),
		FUSE_OPT_END
	};

	myencfs_system system = NULL;

	struct myencfs_fuse_private private[1];
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	FILE *fp_log = NULL;
	int ret = 1;

	memset(private, 0, sizeof(*private));
	private->options->log_level = FUSE_LOG_INFO;
	private->options->max_size = _MYENCFS_DEFAULT_MAX_SIZE;

	if (fuse_opt_parse(&args, private->options, option_spec, NULL) == -1) {
		fprintf(stderr, "Cannot parse options\n");
		goto cleanup;
	}

	if (private->options->show_help) {
		char *help_argv[] = {argv[0], "--help"};
		int help_argc = sizeof(help_argv) / sizeof(*help_argv);
		struct fuse_args help_args = FUSE_ARGS_INIT(help_argc, help_argv);
		ret = fuse_main(help_args.argc, help_args.argv, &__fuse_oper, NULL);
		__show_help();
		fuse_opt_free_args(&help_args);
		goto cleanup;
	}

	if (private->options->key_store == NULL) {
		fprintf(stderr, "Please specify key store directory\n");
		goto cleanup;
	}

	if (private->options->base == NULL) {
		fprintf(stderr, "Please specify base directory\n");
		goto cleanup;
	}

	if ((system = myencfs_system_new()) == NULL) {
		fprintf(stderr, "Cannot create system\n");
	        goto cleanup;
	}

	if (!myencfs_system_construct(system)) {
		fprintf(stderr, "Cannot construct system\n");
	        goto cleanup;
	}

	if ((private->context = myencfs_context_new(system)) == NULL) {
		fprintf(stderr, "Cannot create context\n");
		goto cleanup;
	}

	if (!myencfs_context_construct(private->context)) {
		fprintf(stderr, "Cannot construct context instance\n");
		goto cleanup;
	}

	if (!myencfs_context_set_user_context(private->context, private)) {
		fprintf(stderr, "Cannot set user context\n");
	}

	if ((private->myencfs = myencfs_new(private->context)) == NULL) {
		fprintf(stderr, "Cannot create instance\n");
		goto cleanup;
	}

	if (!myencfs_construct(private->myencfs)) {
		fprintf(stderr, "Cannot construct instance\n");
		goto cleanup;
	}

	if (!myencfs_set_key_callback(private->myencfs, __key_callback)) {
		fprintf(stderr, "Cannot set key callback\n");
	}

	if (!myencfs_set_base_ct(private->myencfs, private->options->base)) {
		fprintf(stderr, "Cannot set base\n");
		goto cleanup;
	}

	if (private->options->md_suffix != NULL) {
		myencfs_set_md_suffix(private->myencfs, private->options->md_suffix);
	}

	private->fp_log = stderr;
	if (private->options->log_file != NULL) {
		if ((fp_log = private->fp_log = fopen(private->options->log_file, "a")) == NULL) {
			goto cleanup;
		}
	}
	fuse_set_log_func(__fuse_log);
	ret = fuse_main(args.argc, args.argv, &__fuse_oper, &private);

cleanup:

	if (private->context != NULL) {
		if (myencfs_error_has_error(myencfs_context_get_error(private->context))) {
			char buf[1024];
			myencfs_error_format(myencfs_context_get_error(private->context), buf, sizeof(buf));
			fputs(buf, private->fp_log);
		}
	}

	if (fp_log != NULL) {
		fclose(fp_log);
	}
	myencfs_destruct(private->myencfs);
	myencfs_context_destruct(private->context);
	myencfs_system_destruct(system);

	fuse_opt_free_args(&args);
	return ret;
}
