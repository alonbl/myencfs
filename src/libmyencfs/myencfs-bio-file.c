#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-bio-file.h>

#include "myencfs-util.h"
#include "myencfs-error-internal.h"

typedef struct __file_private_s {
	myencfs_context context;
	char *path;
	FILE *fp;
} *__file_private;

static
myencfs_error_entry
__error_entry_base(
	const __file_private private,
	const myencfs_error_entry entry
) {
	if (private != NULL) {
		_myencfs_error_entry_prm_add_str(
			entry,
			MYENCFS_ERROR_KEY_RESOURCE_NAME,
			private->path
		);
	}
	return entry;
}

static
myencfs_error_entry
__error_entry_errno(
	const myencfs_error_entry entry
) {
	char msg[1024];
	int old_errno;

	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_ERRNO, errno);

	old_errno = errno;
	errno = 0;
	msg[0] = '\0';
	strerror_r(old_errno, msg, sizeof(msg));
	if (errno == 0) {
		_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_ERRNO_STR, msg);
	}
	errno = old_errno;

	return entry;
}

static
int
__file_close(
	void *_private
) {
	__file_private private = (__file_private)_private;
	if (private->fp != NULL) {
		fclose(private->fp);
		private->fp = NULL;
	}
	return 0;
}

static
bool
__file_destruct(
	void *_private
) {
	__file_private private = (__file_private)_private;
	bool ret = true;

	if (private != NULL) {
		myencfs_system system = myencfs_context_get_system(private->context);

		if (__file_close(private) != 0) {
			ret = false;
		}

		if (
			!myencfs_system_free(system, "myencfs_bio_file::path", private->path) ||
			!myencfs_system_free(system, "myencfs_bio_file", private)
		) {
			ret = false;
		}
	}

	return ret;
}

static
ssize_t
__file_read(
	void *_private,
	void * const buf,
	const size_t size
) {
	__file_private private = (__file_private)_private;
	ssize_t ret = -1;
	size_t n;

	n = fread(buf, 1, size, private->fp);

	if (n == 0 && ferror(private->fp)) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				__error_entry_errno(
					_myencfs_error_capture(myencfs_context_get_error(private->context))
				),
				"read",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot read file '%s'",
				private->path
			)
		));
		goto cleanup;
	}

	ret = (ssize_t)n;

cleanup:

	return ret;
}

static
ssize_t
__file_write(
	void *_private,
	const void * const buf,
	const size_t size
) {
	__file_private private = (__file_private)_private;
	ssize_t ret = -1;
	size_t n;

	n = fwrite(buf, 1, size, private->fp);

	if (n == 0) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				__error_entry_errno(
					_myencfs_error_capture(myencfs_context_get_error(private->context))
				),
				"read",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot write file '%s'",
				private->path
			)
		));
		goto cleanup;
	}

	ret = (ssize_t)n;

cleanup:

	return ret;
}

static
int
__file_seek(
	void *_private,
	ssize_t offset,
	int whence
) {
	__file_private private = (__file_private)_private;
	int ret = -1;

	if (fseek(private->fp, offset, whence) == -1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				__error_entry_errno(
					_myencfs_error_capture(myencfs_context_get_error(private->context))
				),
				"seek",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot seek file '%s'",
				private->path
			)
		));
		goto cleanup;
	}

	ret = 0;

cleanup:

	return ret;
}

static
ssize_t
__file_tell(
	void *_private
) {
	__file_private private = (__file_private)_private;
	ssize_t ret = -1;
	long n;

	if ((n = ftell(private->fp)) == -1) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				__error_entry_errno(
					_myencfs_error_capture(myencfs_context_get_error(private->context))
				),
				"seek",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Cannot get file '%s' position",
				private->path
			)
		));
		goto cleanup;
	}

	ret = (ssize_t)n;

cleanup:

	return ret;
}

static myencfs_bio_callbacks __myencfs_bio_callbacks_file = {
	__file_destruct,
	__file_close,
	__file_read,
	__file_write,
	__file_seek,
	__file_tell,
	NULL
};

myencfs_bio
myencfs_bio_file(
	const myencfs_context context,
	const char * const path,
	const char * const mode
) {
	myencfs_system system = myencfs_context_get_system(context);
	myencfs_bio bio = NULL;
	__file_private private = NULL;
	char buf[1024];
	myencfs_bio ret = NULL;

	if ((private = myencfs_system_zalloc(system, "myencfs_bio_file", sizeof(*private))) == NULL) {
		goto cleanup;
	}

	private->context = context;

	if ((private->path = myencfs_system_strdup(system, "myencfs_bio_file::path", path)) == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(private->context)),
				"bio_file.dup",
				MYENCFS_ERROR_CODE_MEMORY,
				true,
				NULL
			)
		));
		goto cleanup;
	}

	if ((private->fp = fopen(path, mode)) == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			private,
			_myencfs_error_entry_base(
				__error_entry_errno(
					_myencfs_error_capture(myencfs_context_get_error(private->context))
				),
				"bio_file.open",
				MYENCFS_ERROR_CODE_RESOURCE_ACCESS,
				true,
				"Cannot open file '%s' for '%s'",
				path,
				mode
			)
		));
		goto cleanup;
	}

	if ((bio = myencfs_bio_new(context)) == NULL) {
		goto cleanup;
	}

	if (
		!myencfs_bio_construct(
			bio,
			_myencfs_util_snprintf(buf, sizeof(buf), "bio_file::%s", path),
			&__myencfs_bio_callbacks_file,
			sizeof(__myencfs_bio_callbacks_file),
			private
		)
	) {
		goto cleanup;
	}
	private = NULL;

	ret = bio;
	bio = NULL;

cleanup:

	myencfs_bio_destruct(bio);
	__file_destruct(private);

	return ret;
}
