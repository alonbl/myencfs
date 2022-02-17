#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <myencfs/myencfs-bio-file.h>

#include "myencfs-bio-util.h"
#include "myencfs-error-internal.h"

ssize_t
_myencfs_bio_util_read_full_or_eof(
	const myencfs_bio bio,
	void * const _p,
	const size_t _s
) {
	unsigned char *p = (unsigned char *)_p;
	size_t s = _s;
	ssize_t n;
	ssize_t t = 0;
	ssize_t ret = -1;

	while ((n = myencfs_bio_read(bio, p, s)) > 0) {
		p += n;
		s -= n;
		t += n;
	}
	if (n == -1) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(myencfs_bio_get_context(bio))),
			"bio.readfull.eof",
			MYENCFS_ERROR_CODE_IO,
			true,
			"Failed to read entire content"
		));
		goto cleanup;
	}

	ret = t;

cleanup:

	return ret;
}

ssize_t
_myencfs_bio_util_read_full(
	const myencfs_bio bio,
	void * const p,
	const size_t s
) {
	ssize_t n;
	ssize_t ret = -1;

	if ((n = _myencfs_bio_util_read_full_or_eof(bio, p, s)) == -1) {
		_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
			_myencfs_error_capture(myencfs_context_get_error(myencfs_bio_get_context(bio))),
			"bio.readfull",
			MYENCFS_ERROR_CODE_IO,
			true,
			"Failed to read entire content"
		));
		goto cleanup;
	}

	ret = n;

cleanup:

	return ret;
}

ssize_t
_myencfs_bio_util_write_full(
	const myencfs_bio bio,
	const void * const _p,
	const size_t _s
) {
	const unsigned char *p = (const unsigned char *)_p;
	size_t s = _s;
	ssize_t ret = -1;

	while (s > 0) {
		ssize_t n;

		if ((n = myencfs_bio_write(bio, p, s)) == -1) {
			_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(myencfs_bio_get_context(bio))),
				"bio.readfull",
				MYENCFS_ERROR_CODE_IO,
				true,
				"Failed to write entire content"
			));
			goto cleanup;
		}

		p += n;
		s -= n;
	}

	ret = _s;

cleanup:

	return ret;
}

ssize_t
_myencfs_bio_util_read_uint32(
	const myencfs_bio bio,
	uint32_t * const u
) {
	uint32_t _u;
	ssize_t ret = -1;

	if ((ret = _myencfs_bio_util_read_full(bio, &_u, sizeof(_u))) == -1) {
		goto cleanup;
	}

	*u = le64toh(_u);

cleanup:

	return ret;
}

ssize_t
_myencfs_bio_util_write_uint32(
	const myencfs_bio bio,
	const uint32_t u
) {
	uint32_t _u = htole32(u);
	return _myencfs_bio_util_write_full(bio, &_u, sizeof(_u));
}

ssize_t
_myencfs_bio_util_read_uint64(
	const myencfs_bio bio,
	uint64_t * const u
) {
	uint64_t _u;
	ssize_t ret = -1;

	if ((ret = _myencfs_bio_util_read_full(bio, &_u, sizeof(_u))) == -1) {
		goto cleanup;
	}

	*u = le64toh(_u);

cleanup:

	return ret;
}

ssize_t
_myencfs_bio_util_write_uint64(
	const myencfs_bio bio,
	const uint64_t u
) {
	uint64_t _u = htole64(u);
	return _myencfs_bio_util_write_full(bio, &_u, sizeof(_u));
}
