#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <myencfs/myencfs-bio-file.h>

#include "myencfs-private.h"
#include "myencfs-system-driver-core.h"

struct __myencfs_s {
	myencfs_context context;
	struct _myencfs_internal_s internal[1];
};

myencfs_error_entry
__myencfs_error_entry_base(
	const myencfs myencfs __attribute__((unused)),
	const myencfs_error_entry entry
) {
	return entry;
}

static
bool
__myencfs_set_property_string(
	const myencfs myencfs,
	const char * const name,
	const char * const src,
	char **dst
) {
	myencfs_system system = myencfs_get_system(myencfs);
	char *s = NULL;
	bool ret = false;

	if (myencfs == NULL) {
		return false;
	}

	if (src != NULL) {
		if ((s = myencfs_system_strdup(system, name, src)) == NULL) {
			goto cleanup;
		}
	}

	if (!myencfs_system_free(system, name, *dst)) {
		goto cleanup;
	}

	*dst = s;
	s = NULL;

	ret = true;

cleanup:

	myencfs_system_free(system, name, s);

	return ret;
}


#if defined(ENABLE_BIO_FILE)

static
bool
__myencfs_util_is_file_name_valid(
	const char * const name
) {
	bool ret = false;

	if (strstr(name, "/../") != NULL) {
		goto cleanup;
	}

	if (!strncmp(name, "../", 3)) {
		goto cleanup;
	}

	if (strlen(name) > 3 && !strncmp(name+strlen(name)-3, "/..", 3)) {
		goto cleanup;
	}

	if (strchr(name, ':') != NULL) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

myencfs_bio
__myencfs_file_open(
	const myencfs myencfs,
	const char * const mode,
	const char * const base,
	const char * const name,
	const char * const suffix
) {
	myencfs_system system = myencfs_get_system(myencfs);
	const char *_suffix = suffix;
	char *file = NULL;
	char *dir = NULL;
	myencfs_bio bio = NULL;
	myencfs_bio ret = NULL;

	if (_suffix == NULL) {
		_suffix = "";
	}

	if (!__myencfs_util_is_file_name_valid(name)) {
		goto cleanup;
	}

	if ((file = myencfs_system_realloc(
		system,
		"__myencfs_file_open::path",
		NULL,
		strlen(base) + strlen(name) + strlen(_suffix) + 2
	)) == NULL) {
		goto cleanup;
	}

	sprintf(file, "%s%c%s%s", base, _MYENCFS_PATH_SEPARTOR, name, _suffix);

	if (strchr(name, _MYENCFS_PATH_SEPARTOR) != NULL && strchr(mode, 'w') != NULL) {
		if ((dir = myencfs_system_strdup(system, "__myencfs_file_open::dir", file)) == NULL) {
			goto cleanup;
		}

		*strrchr(dir, _MYENCFS_PATH_SEPARTOR) = '\0';

		if (!myencfs_system_driver_core_access(system)(system, dir, F_OK)) {
			if (!myencfs_system_driver_core_mkdir(system)(system, dir, 0770)) {
				_myencfs_error_entry_dispatch(_myencfs_error_entry_base(
					_myencfs_error_capture(myencfs_get_error(myencfs)),
					"mycms.open",
					MYENCFS_ERROR_CODE_IO,
					false,
					"Failed to create directory '%s'",
					dir
				));
			}
		}
	}

	if ((bio = myencfs_bio_file(myencfs_get_context(myencfs), file, mode)) == NULL) {
		goto cleanup;
	}

	ret = bio;
	bio = NULL;

cleanup:

	myencfs_bio_destruct(bio);
	myencfs_system_free(system, "__myencfs_file_open::file", file);
	myencfs_system_free(system, "__myencfs_file_open::dir", dir);

	return ret;
}

#endif

myencfs
myencfs_new(
	const myencfs_context context
) {
	myencfs_system system = myencfs_context_get_system(context);
	myencfs ret = NULL;
	myencfs myencfs = NULL;

	if ((myencfs = myencfs_system_zalloc(system, "myencfs", sizeof(*myencfs))) == NULL) {
		goto cleanup;
	}

	myencfs->context = context;

	if ((myencfs->internal->crypto = _myencfs_crypto_new(myencfs->context)) == NULL) {
		_myencfs_error_entry_dispatch(__myencfs_error_entry_base(
			myencfs,
			_myencfs_error_entry_base(
				_myencfs_error_capture(myencfs_context_get_error(context)),
				"myencfs_new.crypto",
				MYENCFS_ERROR_CODE_MEMORY,
				true,
				NULL
			)
		));
		goto cleanup;
	}

	ret = myencfs;
	myencfs = NULL;

cleanup:

	myencfs_destruct(myencfs);

	return ret;
}

bool
myencfs_construct(
	const myencfs myencfs
) {
	bool ret = false;

	if (myencfs == NULL) {
		return false;
	}

	if (!_myencfs_crypto_construct(myencfs->internal->crypto)) {
		goto cleanup;
	}

	if (!myencfs_set_md_suffix(myencfs, _MYENCFS_MD_SUFFIX)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
myencfs_destruct(
	const myencfs myencfs
) {
	int ret = true;

	if (myencfs != NULL) {
		myencfs_system system = myencfs_get_system(myencfs);

		_myencfs_crypto_destruct(myencfs->internal->crypto);

		if (
			!myencfs_system_free(system, "myencfs::base_ct", myencfs->internal->base_ct) ||
			!myencfs_system_free(system, "myencfs::base_pt", myencfs->internal->base_pt) ||
			!myencfs_system_free(system, "myencfs::md_suffix", myencfs->internal->md_suffix) ||
			!myencfs_system_free(system, "myencfs::key_id", myencfs->internal->encryption_key_id) ||
			!myencfs_system_free(system, "myencfs", myencfs)
		) {
			ret = false;
		}
	}

	return ret;
}

myencfs_context
myencfs_get_context(
	const myencfs myencfs
) {
	if (myencfs == NULL) {
		return NULL;
	}

	return myencfs->context;
}

myencfs_system
myencfs_get_system(
	const myencfs myencfs
) {
	if (myencfs == NULL) {
		return NULL;
	}
	return myencfs_context_get_system(myencfs->context);
}

myencfs_error
myencfs_get_error(
	const myencfs myencfs
) {
	return myencfs_context_get_error(myencfs_get_context(myencfs));
}

myencfs_internal
_myencfs_get_internal(
	const myencfs myencfs
) {
	if (myencfs == NULL) {
		return NULL;
	}
	return myencfs->internal;
}

bool
myencfs_set_base_ct(
	const myencfs myencfs,
	const char * const base_ct
) {
	return __myencfs_set_property_string(
		myencfs,
		"base_ct",
		base_ct,
		&myencfs->internal->base_ct
	);
}

bool
myencfs_set_base_pt(
	const myencfs myencfs,
	const char * const base_pt
) {
	return __myencfs_set_property_string(
		myencfs,
		"base_pt",
		base_pt,
		&myencfs->internal->base_pt
	);
}

bool
myencfs_set_key_callback(
	const myencfs myencfs,
	const myencfs_key_callback callback
) {
	if (myencfs == NULL) {
		return false;
	}

	myencfs->internal->key_callback = callback;

	return true;
}

bool
myencfs_set_encryption_key_id(
	const myencfs myencfs,
	const char * const encryption_key_id
) {
	return __myencfs_set_property_string(
		myencfs,
		"encryption_key_id",
		encryption_key_id,
		&myencfs->internal->encryption_key_id
	);
}

const char *
myencfs_get_md_suffix(
	const myencfs myencfs
) {
	if (myencfs == NULL) {
		return NULL;
	}
	return myencfs->internal->md_suffix;
}

bool
myencfs_set_md_suffix(
	const myencfs myencfs,
	const char * const md_suffix
) {
	return __myencfs_set_property_string(
		myencfs,
		"md_suffix",
		md_suffix,
		&myencfs->internal->md_suffix
	);
}
