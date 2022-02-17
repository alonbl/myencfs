#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <myencfs/myencfs-bio.h>

#include "myencfs-error-internal.h"
#include "myencfs-util.h"

struct __myencfs_bio_s {
	myencfs_context context;
	char name[256];
	void *private;
	myencfs_bio_callbacks c;
};

static
myencfs_error_entry
__error_entry_base(
	const myencfs_bio bio,
	const myencfs_error_entry entry
) {
	if (bio != NULL) {
		_myencfs_error_entry_prm_add_str(
			entry,
			MYENCFS_ERROR_KEY_RESOURCE_NAME,
			bio->name
		);
	}
	return entry;
}

bool
myencfs_bio_copy(
	const myencfs_context context,
	const myencfs_bio dst,
	const myencfs_bio src,
	const bool do_close
) {
	myencfs_error error = myencfs_context_get_error(context);
	unsigned char buf[_MYENCFS_IO_BLOCK_SIZE];
	ssize_t s;
	bool ret = false;

	if (context == NULL) {
		goto cleanup;
	}

	if (dst == NULL || src == NULL) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(error),
			"copy,sanity",
			MYENCFS_ERROR_CODE_ARGS,
			true,
			"BIO is null"
		));
	}

	while ((s = myencfs_bio_read(src, buf, sizeof(buf))) > 0) {
		unsigned char *p = buf;
		while (s > 0) {
			ssize_t n;
			if ((n = myencfs_bio_write(dst, p, s)) == -1) {
				_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
					_myencfs_error_capture(error),
					"bio_copy::write",
					MYENCFS_ERROR_CODE_IO,
					true,
					"BIO copy '%s'->'%s' write failed",
					myencfs_bio_get_name(src),
					myencfs_bio_get_name(dst)
				));
				goto cleanup;
			}
			p += n;
			s -= n;
		}
	}
	if (s < 0) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(error),
			"bio_copy::read",
			MYENCFS_ERROR_CODE_IO,
			true,
			"BIO copy '%s'->'%s' read failed",
			myencfs_bio_get_name(src),
			myencfs_bio_get_name(dst)
		));
		goto cleanup;
	}

	if (do_close) {
		if (myencfs_bio_close(dst) == -1) {
			_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
				_myencfs_error_capture(error),
				"bio_copy::close",
				MYENCFS_ERROR_CODE_IO,
				true,
				"BIO copy '%s'->'%s' closed failed",
				myencfs_bio_get_name(src),
				myencfs_bio_get_name(dst)
			));
			goto cleanup;
		}
	}

	ret = true;

cleanup:

	return ret;
}

myencfs_bio
myencfs_bio_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	myencfs_bio ret = NULL;

	if ((ret = myencfs_system_zalloc(system, "myencfs_bio", sizeof(*ret))) == NULL) {
		goto cleanup;
	}

	ret->context = context;

cleanup:

	return ret;
}

bool
myencfs_bio_construct(
	const myencfs_bio bio,
	const char * const name,
	const myencfs_bio_callbacks *const callbacks,
	const size_t callbacks_size,
	void *private
) {
	bool ret = false;

	if (bio == NULL) {
		return 0;
	}

	if (sizeof(myencfs_bio_callbacks) < callbacks_size) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"args",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Callbacks vector overflow max=%ld actual=%ld",
				(long)sizeof(myencfs_bio_callbacks),
				(long)callbacks_size
			)
		));
		goto cleanup;
	}


	bio->private = private;
	strncpy(bio->name, name, sizeof(bio->name) - 1);
	memcpy(&bio->c, callbacks, callbacks_size);

	ret = true;

cleanup:

	return ret;
}

bool
myencfs_bio_destruct(
	const myencfs_bio bio
) {
	bool ret = true;

	if (bio != NULL) {
		myencfs_system system = myencfs_context_get_system(bio->context);

		if (bio->c.destruct != NULL) {
			if (!bio->c.destruct(bio->private)) {
				ret = false;
			}
		}

		if (!myencfs_system_free(system, "myencfs_bio", bio)) {
			ret = false;
		}
	}

	return ret;
}

myencfs_context
myencfs_bio_get_context(
	const myencfs_bio bio
) {
	if (bio == NULL) {
		return NULL;
	}
	return bio->context;
}

const char *
myencfs_bio_get_name(
	const myencfs_bio bio
) {
	if (bio == NULL) {
		return NULL;
	}
	return bio->name;
}

int
myencfs_bio_close(
	const myencfs_bio bio
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.close == NULL) {
		return 0;
	}
	return bio->c.close(bio->private);
}

ssize_t
myencfs_bio_read(
	const myencfs_bio bio,
	void * const buf,
	const size_t size
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.read == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"sanity",
				MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
				true,
				"Read is not implemented"
			)
		));
		return -1;
	}
	return bio->c.read(bio->private, buf, size);
}

ssize_t
myencfs_bio_write(
	const myencfs_bio bio,
	const void * const buf,
	const size_t size
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.write == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"sanity",
				MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
				true,
				"Write is not implemented"
			)
		));
		return -1;
	}
	return bio->c.write(bio->private, buf, size);
}

int
myencfs_bio_seek(
	const myencfs_bio bio,
	ssize_t offset,
	int whence
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.seek == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"sanity",
				MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
				true,
				"Seek is not implemented"
			)
		));
		return -1;
	}
	return bio->c.seek(bio->private, offset, whence);
}

ssize_t
myencfs_bio_tell(
	const myencfs_bio bio
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.tell == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"sanity",
				MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
				true,
				"Tell is not implemented"
			)
		));
		return -1;
	}
	return bio->c.tell(bio->private);
}

ssize_t
myencfs_bio_control(
	const myencfs_bio bio,
	const int command,
	const void * const in,
	const size_t in_size,
	void * const out,
	const size_t out_size
) {
	if (bio == NULL) {
		return -1;
	}
	if (bio->c.control == NULL) {
		_myencfs_error_entry_dispatch(__error_entry_base(
			bio,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(bio->context)),
				"sanity",
				MYENCFS_ERROR_CODE_NOT_IMPLEMENTED,
				true,
				"Control is not implemented"
			)
		));
		return -1;
	}
	return bio->c.control(bio->private, command, in, in_size, out, out_size);
}

static
ssize_t
__null_write(
	void *_private __attribute__((unused)),
	const void * const buf __attribute__((unused)),
	const size_t size
) {
	return size;
}

static myencfs_bio_callbacks __myencfs_bio_callbacks_null = {
	NULL,
	NULL,
	NULL,
	__null_write,
	NULL,
	NULL,
	NULL
};

myencfs_bio
myencfs_bio_null(
	const myencfs_context context
) {
	myencfs_bio bio = NULL;
	myencfs_bio ret = NULL;


	if ((bio = myencfs_bio_new(context)) == NULL) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(bio->context)),
			"myencfs_bio_null",
			MYENCFS_ERROR_CODE_MEMORY,
			true,
			NULL
		));
		goto cleanup;
	}

	if (!myencfs_bio_construct(
		bio,
		"bio::null",
		&__myencfs_bio_callbacks_null,
		sizeof(__myencfs_bio_callbacks_null),
		NULL
	)) {
		goto cleanup;
	}

	ret = bio;
	bio = NULL;

cleanup:

	myencfs_bio_destruct(bio);

	return ret;
}

#define __MYCRYPTFS_BIO_MEM_CMD_RESET 1
#define __MYCRYPTFS_BIO_MEM_CMD_GET_POINTER 2
#define __MYCRYPTFS_BIO_MEM_CMD_GET_MAX_SIZE 3
#define __MEM_BLOCK_SIZE 4096

typedef struct __mem_private_s {
	myencfs_context context;
	myencfs_bio bio;
	unsigned char *buf;
	size_t pos;
	size_t size;
	size_t max;
	bool fixed;
} *__mem_private;

static
myencfs_error_entry
__mem_error_entry_base(
	const __mem_private private,
	const myencfs_error_entry entry
) {
	if (private != NULL) {
		_myencfs_error_entry_prm_add_str(
			entry,
			MYENCFS_ERROR_KEY_RESOURCE_NAME,
			myencfs_bio_get_name(private->bio)
		);
	}
	return entry;
}

static
bool
__mem_destruct(
	void *_private
) {
	__mem_private private = (__mem_private)_private;
	bool ret = true;

	if (private != NULL) {
		myencfs_system system = myencfs_context_get_system(private->context);

		if (!private->fixed) {
			if (!myencfs_system_free(system, "myencfs_bio_mem::buf", private->buf)) {
				ret = false;
			}
		}
		if (!myencfs_system_free(system, "myencfs_bio_mem", private)) {
			ret = false;
		}
	}

	return ret;
}

static
ssize_t
__mem_read(
	void *_private,
	void * const buf,
	const size_t size
) {
	__mem_private private = (__mem_private)_private;
	size_t n;

	if (size == 0) {
		return 0;
	}

	if (buf == NULL) {
		_myencfs_error_entry_dispatch(__mem_error_entry_base(
			private,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(private->context)),
				"mem_read",
				MYENCFS_ERROR_CODE_ARGS,
				true,
				"Buffer is null"
			)
		));
		return -1;
	}

	if (private->size - private->pos < size) {
		n = private->size - private->pos;
	}
	else {
		n = size;
	}

	memcpy(buf, private->buf + private->pos, n);
	private->pos += n;

	return n;
}

static
ssize_t
__mem_write(
	void *_private,
	const void * const buf,
	const size_t size
) {
	__mem_private private = (__mem_private)_private;
	myencfs_system system = myencfs_context_get_system(private->context);
	ssize_t ret = -1;

	if (buf == NULL) {
		if (size == 0) {
			return 0;
		}
		else {
			_myencfs_error_entry_dispatch(__mem_error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_context_get_error(private->context)),
					"mem_write.args",
					MYENCFS_ERROR_CODE_ARGS,
					true,
					"Buffer is null"
				)
			));
			return -1;
		}
	}

	if (size > private->max - private->pos) {
		unsigned char *p;
		size_t n;

		if (private->fixed) {
			_myencfs_error_entry_dispatch(__mem_error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_context_get_error(private->context)),
					"mem_write",
					MYENCFS_ERROR_CODE_STATE,
					true,
					"Attempt to extend fixed buffer bio"
				)
			));
			goto cleanup;
		}

		n = private->pos + size + __MEM_BLOCK_SIZE;
		if ((p = myencfs_system_realloc(system, "myencfs_bio_mem::buf", private->buf, n)) == NULL) {
			_myencfs_error_entry_dispatch(__mem_error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_context_get_error(private->context)),
					"mem_write.buf.alloc",
					MYENCFS_ERROR_CODE_MEMORY,
					true,
					NULL
				)
			));
			goto cleanup;
		}
		private->buf = p;
		private->max = n;
	}

	memcpy(private->buf + private->pos, buf, size);
	private->pos += size;
	if (private->pos > private->size) {
		private->size = private->pos;
	}

	ret = size;

cleanup:

	return ret;
}

static
int
__mem_seek(
	void *_private,
	ssize_t offset,
	int whence
) {
	__mem_private private = (__mem_private)_private;
	int ret = -1;

	switch (whence) {
		default:
			_myencfs_error_entry_dispatch(__mem_error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_context_get_error(private->context)),
					"mem_seek.whence",
					MYENCFS_ERROR_CODE_ARGS,
					true,
					"Unsupported whence %d",
					whence
				)
			));
			goto cleanup;
		case SEEK_SET:
			if (offset < 0 || offset > (ssize_t)private->size) {
				_myencfs_error_entry_dispatch(__mem_error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_context_get_error(private->context)),
						"mem_seek.whence",
						MYENCFS_ERROR_CODE_ARGS,
						true,
						"Offset %ld is out of range max is %ld",
						(long)offset,
						(long)private->size
					)
				));
				goto cleanup;
			}
			private->pos = offset;
		break;
		case SEEK_CUR:
			if ((ssize_t)private->pos + offset < 0 || (ssize_t)private->pos + offset > (ssize_t)private->size) {
				_myencfs_error_entry_dispatch(__mem_error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_context_get_error(private->context)),
						"mem_seek.cur",
						MYENCFS_ERROR_CODE_ARGS,
						true,
						"Offset %ld at position %ld is out of range max is %ld",
						(long)offset,
						(long)private->pos,
						(long)private->size
					)
				));
				goto cleanup;
			}
			private->pos += offset;
		break;
		case SEEK_END:
			if ((ssize_t)private->size + offset < 0 || (ssize_t)private->size + offset > (ssize_t)private->size) {
				_myencfs_error_entry_dispatch(__mem_error_entry_base(
					private,
					_myencfs_error_entry_base(
						_myencfs_error_capture(myencfs_context_get_error(private->context)),
						"mem_seek.end",
						MYENCFS_ERROR_CODE_ARGS,
						true,
						"Offset %ld is out of range max is %ld",
						(long)offset,
						(long)private->size
					)
				));
				goto cleanup;
			}
			private->pos = private->size + offset;
		break;
	}

	ret = 0;

cleanup:

	return ret;
}

static
ssize_t
__mem_tell(
	void *_private
) {
	__mem_private private = (__mem_private)_private;
	return private->pos;
}

static
ssize_t
__mem_control(
	void *_private,
	const int command,
	const void * const in __attribute__((unused)),
	const size_t in_size __attribute__((unused)),
	void * const out,
	const size_t out_size
) {
	__mem_private private = (__mem_private)_private;
	ssize_t ret = -1;

	switch (command) {
		default:
			_myencfs_error_entry_dispatch(__mem_error_entry_base(
				private,
				_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_context_get_error(private->context)),
					"control.command",
					MYENCFS_ERROR_CODE_ARGS,
					true,
					"Invalid control command %d",
					command
				)
			));
			goto cleanup;
		case __MYCRYPTFS_BIO_MEM_CMD_RESET:
			private->pos = 0;
			private->size = 0;
			ret = 0;
		break;
		case __MYCRYPTFS_BIO_MEM_CMD_GET_POINTER:
			if (out != NULL) {
				if (out_size < sizeof(void *)) {
					_myencfs_error_entry_dispatch(__mem_error_entry_base(
						private,
						_myencfs_error_entry_base(
							_myencfs_error_capture(myencfs_context_get_error(private->context)),
							"control.get-pointer",
							MYENCFS_ERROR_CODE_ARGS,
							true,
							"Output buffer is too small"
						)
					));
					goto cleanup;
				}
				*(void **)out = private->buf;
			}
			ret = private->size;
		break;
		case __MYCRYPTFS_BIO_MEM_CMD_GET_MAX_SIZE:
			if (out != NULL) {
				if (out_size < sizeof(void *)) {
					_myencfs_error_entry_dispatch(__mem_error_entry_base(
						private,
						_myencfs_error_entry_base(
							_myencfs_error_capture(myencfs_context_get_error(private->context)),
							"control.get-max-size",
							MYENCFS_ERROR_CODE_ARGS,
							true,
							"Output buffer is too small"
						)
					));
					goto cleanup;
				}
				*(void **)out = private->buf;
			}
			ret = private->max;
		break;
	}

cleanup:

	return ret;
}

static myencfs_bio_callbacks __myencfs_bio_callbacks_mem = {
	__mem_destruct,
	NULL,
	__mem_read,
	__mem_write,
	__mem_seek,
	__mem_tell,
	__mem_control
};

static
myencfs_bio
__mem(
	const myencfs_context context,
	const char * const name,
	unsigned char * const buf,
	const size_t size,
	const size_t max_size
) {
	myencfs_system system = myencfs_context_get_system(context);
	__mem_private private = NULL;
	char strbuf[1024];
	myencfs_bio ret = NULL;

	if ((private = myencfs_system_zalloc(system, "myencfs_bio_mem", sizeof(*private))) == NULL) {
		goto cleanup;
	}

	private->context = context;
	private->buf = buf;
	private->size = size;
	private->max = max_size;
	private->fixed = buf != NULL;

	if ((private->bio = myencfs_bio_new(context)) == NULL) {
		goto cleanup;
	}

	if (!myencfs_bio_construct(
		private->bio,
		_myencfs_util_snprintf(strbuf, sizeof(strbuf), "bio_mem::%s", name),
		&__myencfs_bio_callbacks_mem,
		sizeof(__myencfs_bio_callbacks_mem),
		private
	)) {
		goto cleanup;
	}
	ret = private->bio;
	private = NULL;

cleanup:
	if (private != NULL) {
		myencfs_bio_destruct(private->bio);
		__mem_destruct(private);
	}

	return ret;
}

myencfs_bio
myencfs_bio_mem(
	const myencfs_context context,
	const char * const name
) {
	return __mem(context, name, NULL, 0, 0);
}

myencfs_bio
myencfs_bio_mem_buf(
	const myencfs_context context,
	const char * const name,
	unsigned char * const buf,
	const size_t size,
	const size_t max_size
) {
	return __mem(context, name, buf, size, max_size);
}

bool
myencfs_bio_mem_reset(
	const myencfs_bio bio
) {
	return myencfs_bio_control(bio, __MYCRYPTFS_BIO_MEM_CMD_RESET, NULL, 0, NULL, 0) != -1;
}

size_t
myencfs_bio_mem_get_data(
	const myencfs_bio bio,
	void **p
) {
	return myencfs_bio_control(bio, __MYCRYPTFS_BIO_MEM_CMD_GET_POINTER, NULL, 0, p, sizeof(*p));
}

size_t
myencfs_bio_mem_get_max_size(
	const myencfs_bio bio,
	void **p
) {
	return myencfs_bio_control(bio, __MYCRYPTFS_BIO_MEM_CMD_GET_MAX_SIZE, NULL, 0, p, sizeof(*p));
}
