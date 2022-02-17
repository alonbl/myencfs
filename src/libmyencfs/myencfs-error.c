#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "myencfs-error-internal.h"
#include "myencfs-util.h"

#define __MYENCFS_ERROR_MAX_KEY_DESC 256
#define __MYENCFS_ERROR_MAX_ENTRIES 50
#define __MYENCFS_ERROR_MAX_PRMS 20

struct __myencfs_error_entry_s {
	myencfs_error error;
	unsigned n;
	struct myencfs_error_prm_s prms[__MYENCFS_ERROR_MAX_PRMS];
};

struct __myencfs_error_s {
	myencfs_system system;
	myencfs_variant vars[__MYENCFS_ERROR_MAX_ENTRIES][__MYENCFS_ERROR_MAX_PRMS];
	unsigned entries_num;
	struct __myencfs_error_entry_s entries[__MYENCFS_ERROR_MAX_ENTRIES];
};

static struct myencfs_error_desc_s __common_error_key_desc[] = {
	{MYENCFS_ERROR_KEY_AUTHORITATIVE, "AUTHORITATIVE", "%ld"},
	{MYENCFS_ERROR_KEY_CODE, "CODE", "0x%08lx"},
	{MYENCFS_ERROR_KEY_SOURCE_FILE, "SOURCE_FILE", "%s"},
	{MYENCFS_ERROR_KEY_SOURCE_LINE, "SOURCE_LINE", "%ld"},
	{MYENCFS_ERROR_KEY_SOURCE_FUNC, "SOURCE_FUNC", "%s"},
	{MYENCFS_ERROR_KEY_HINT, "HINT", "%s"},
	{MYENCFS_ERROR_KEY_DESCRIPTION, "DESCRIPTION", "%s"},
	{MYENCFS_ERROR_KEY_RESOURCE_SIZE, "RESOURCE_SIZE", "%lld"},
	{MYENCFS_ERROR_KEY_RESOURCE_NAME, "RESOURCE_NAME", "%s"},
	{MYENCFS_ERROR_KEY_ERRNO, "ERRNO", "%ld"},
	{MYENCFS_ERROR_KEY_ERRNO_STR, "ERRNO_STR", "%s"},
	{MYENCFS_ERROR_KEY_NTSTATUS, "NTSTATUS", "%08x"},
	{MYENCFS_ERROR_KEY_MBED_STATUS, "MBED_STATUS", "%ld"},
	{MYENCFS_ERROR_KEY_OPENSSL_STATUS, "OPENSSL_STATUS", "%ld"},
	{MYENCFS_ERROR_KEY_OPENSSL_STATUS_STR, "OPENSSL_STATUS_STR", "%s"}
};

static struct {
	bool init;
	unsigned error_key_desc_size;
	char error_key_desc_desc[__MYENCFS_ERROR_MAX_KEY_DESC][256];
	char error_key_desc_format[__MYENCFS_ERROR_MAX_KEY_DESC][16];
	struct myencfs_error_desc_s error_key_desc[__MYENCFS_ERROR_MAX_KEY_DESC];
} __private[1];

void
_myencfs_error_static_init(void) {
	if (!__private->init) {
		unsigned i;
		for (i=0;i<__MYENCFS_ERROR_MAX_KEY_DESC;i++) {
			__private->error_key_desc[i].desc = __private->error_key_desc_desc[i];
			__private->error_key_desc[i].format = __private->error_key_desc_format[i];
		}
		_myencfs_error_register_key_desc(
			__common_error_key_desc,
			sizeof(__common_error_key_desc) / sizeof(__common_error_key_desc[0])
		);
		__private->init = true;
	}
}

myencfs_error_desc
myencfs_error_get_key_desc(
	const uint32_t key
) {
	unsigned i;

	for (i=0;i < __private->error_key_desc_size; i++) {
		if (__private->error_key_desc[i].key == key) {
			return &__private->error_key_desc[i];
		}
	}

	return NULL;
}

void
_myencfs_error_register_key_desc(
	struct myencfs_error_desc_s * const _desc,
	const size_t n
) {
	struct myencfs_error_desc_s *last = &__private->error_key_desc[__private->error_key_desc_size];
	struct myencfs_error_desc_s *desc = _desc;
	size_t i;

	for (i=0;i<n;i++) {
		if (__private->error_key_desc_size >= sizeof(__private->error_key_desc) / sizeof(__private->error_key_desc[0])) {
			break;
		}

		last->key = desc->key;
		strncpy(last->desc, desc->desc, sizeof(__private->error_key_desc_desc[0]) - 1);
		strncpy(last->format, desc->format, sizeof(__private->error_key_desc_format[0]) - 1);

		last++;
		desc++;
		__private->error_key_desc_size++;
	}
}

myencfs_error
_myencfs_error_new(
	const myencfs_system system
) {
	myencfs_error error = NULL;
	unsigned i;

	if ((error = myencfs_system_zalloc(system, "myencfs_error", sizeof(*error))) == NULL) {
		goto cleanup;
	}

	error->system = system;

	for (i=0;i < __MYENCFS_ERROR_MAX_ENTRIES;i++) {
		unsigned j;
		error->entries[i].error = error;
		for (j=0;j < __MYENCFS_ERROR_MAX_PRMS;j++) {
			error->entries[i].prms[j].v = &error->vars[i][j];
		}
	}

cleanup:

	return error;
}

bool
_myencfs_error_construct(
	const myencfs_error error __attribute__((unused))
) {
	return true;
}

bool
_myencfs_error_destruct(
	const myencfs_error error
) {
	int ret = true;

	if (error != NULL) {
		ret = myencfs_system_free(error->system, "myencfs_error", error) && ret;
	}

	return ret;
}

bool
myencfs_error_has_error(
	const myencfs_error error
) {
	if (error == NULL) {
		return false;
	}
	return error->entries_num != 0;
}

void
myencfs_error_reset(
	const myencfs_error error
) {
	if (error != NULL) {
		unsigned i;
		for (i=0;i < error->entries_num; i++) {
			error->entries[i].n = 0;
		}
		error->entries_num = 0;
	}
}

bool
myencfs_error_format_callback(
	const myencfs_error error,
	void (*f)(
		const myencfs_error error,
		const unsigned index,
		const myencfs_error_prm prms,
		const unsigned prms_len,
		void *d
	),
	void *p
) {
	unsigned i;

	if (error == NULL) {
		return false;
	}

	for (i=error->entries_num; i > 0; i--) {
		f(error, i-1, error->entries[i-1].prms,  error->entries[i-1].n, p);
	}

	return true;
}

struct __format_state {
	uint32_t *code;
	bool found;
	char *start;
	size_t size;
	char *pos;
	size_t remain;
};

static
void
__format_state_fixup(
	struct __format_state *buf,
	size_t n
) {
	n = _MYENCFS_UTIL_MIN(buf->remain, n);
	buf->pos += n;
	buf->remain -= n;
}

static
void
__format_strncpy(
	char * const dst,
	const char * const src,
	const size_t size
) {
	if (dst != NULL) {
		strncpy(dst, src, size-1);
		dst[size-1] = '\0';
	}
}


static
void
__error_format_simple_callback(
	const myencfs_error error __attribute__((unused)),
	const unsigned index,
	const myencfs_error_prm prms,
	const unsigned prms_len,
	void *d
) {
	struct __format_state *buf = (struct __format_state *)d;

	if (!buf->found) {
		bool found = false;
		unsigned i;

		for (i=0;!found && i < prms_len; i++) {
			if (prms[i].k == MYENCFS_ERROR_KEY_AUTHORITATIVE) {
				found = true;
			}
		}

		if (found || index == 0) {
			buf->found = true;
			for (i=0;i < prms_len; i++) {
				switch (prms[i].k) {
					case MYENCFS_ERROR_KEY_CODE:
						*buf->code = prms[i].v->d->u32;
					break;
					case MYENCFS_ERROR_KEY_DESCRIPTION:
						__format_strncpy(buf->start, prms[i].v->d->str, buf->size - 1);
					break;
				}
			}
		}
	}
}

bool
myencfs_error_format_simple(
	const myencfs_error error,
	uint32_t * const code,
	char * const buf,
	const size_t buf_size
) {
	if (error == NULL) {
		*code = MYENCFS_ERROR_CODE_NO_CONTEXT;
		__format_strncpy(buf, "No context", buf_size - 1);
		goto cleanup;
	} else if (error->entries_num == 0) {
		*code = MYENCFS_ERROR_CODE_SUCCESS;
		__format_strncpy(buf, "Success", buf_size - 1);
		goto cleanup;
	} else {
		struct __format_state _buf[1] = {{code, false, buf, buf_size, buf, buf_size}};
		myencfs_error_format_callback(
			error,
			__error_format_simple_callback,
			_buf
		);
	}

cleanup:

	return *code != MYENCFS_ERROR_CODE_SUCCESS;
}

static
void
__error_format_callback(
	const myencfs_error error __attribute__((unused)),
	const unsigned index,
	const myencfs_error_prm prms,
	const unsigned prms_len,
	void *d
) {
#define __MY_DEF(x, d) ((x) == NULL ? (d) : (x->format))
	struct __format_state *buf = (struct __format_state *)d;
	unsigned i;

	__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "%4s#%d\n", "", index));

	for (i=0;i < prms_len; i++) {
		const myencfs_error_prm prm = &prms[i];
		myencfs_error_desc desc = myencfs_error_get_key_desc(prm->k);
		unsigned n;

		if (desc == NULL) {
			__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "%8s%08lx=", "", (unsigned long)prm->k));
		} else {
			__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "%8s%s=", "", desc->desc));
		}

		switch (prm->v->t) {
			default:
				n = snprintf(buf->pos, buf->remain, "*ERROR*");
			break;
			case myencfs_variant_type_none:
				n = snprintf(buf->pos, buf->remain, "(none)");
			break;
			case myencfs_variant_type_u32:
				n = snprintf(buf->pos, buf->remain, __MY_DEF(desc, "%08lx"), (unsigned long)prm->v->d->u32);
			break;
			case myencfs_variant_type_u64:
				n = snprintf(buf->pos, buf->remain, __MY_DEF(desc, "%08llx"), (unsigned long long)prm->v->d->u64);
			break;
			case myencfs_variant_type_str:
				n = snprintf(buf->pos, buf->remain, __MY_DEF(desc, "%s"), prm->v->d->str);
			break;
			case myencfs_variant_type_blob:
				n = snprintf(buf->pos, buf->remain, "BLOB");
			break;
		}
		__format_state_fixup(buf, n);
		__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "\n"));
	}
#undef __MY_DEF
}

void
myencfs_error_format(
	const myencfs_error error,
	char * const _buf,
	const size_t buf_size
) {
	struct __format_state buf[1] = {{NULL, false, _buf, buf_size, _buf, buf_size}};

	__format_state_fixup(buf, snprintf(
		buf->pos, buf->remain,
		(
			"MYENCFS ERROR DUMP - BEGIN\n"
			"Version: %s-%s (%s)\n"
			"Entries (most recent call last):\n"
		),
		PACKAGE_NAME,
		PACKAGE_VERSION,
		PACKAGE_BUILD_ID
	));

	if (!myencfs_error_format_callback(
		error,
		__error_format_callback,
		buf
	)) {
		__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "%4sNot available\n", ""));
	}

	__format_state_fixup(buf, snprintf(buf->pos, buf->remain, "MYENCFS ERROR DUMP - END\n"));
}

myencfs_error_entry
_myencfs_error_entry_new(
	myencfs_error error
) {
	if (error == NULL) {
		return NULL;
	}
	if (error->entries_num >= __MYENCFS_ERROR_MAX_ENTRIES) {
		return NULL;
	}
	return &error->entries[error->entries_num++];
}

void
_myencfs_error_entry_dispatch(
	const myencfs_error_entry entry __attribute__((unused))
) {
}

 myencfs_variant *
 _myencfs_error_entry_prm_new_variant(
	const myencfs_error_entry entry,
	const int k
) {
	if (entry == NULL) {
		return NULL;
	}

	if (entry->n >= __MYENCFS_ERROR_MAX_PRMS) {
		return NULL;
	} else {
		myencfs_error_prm prm = &entry->prms[entry->n++];
		prm->k = k;
		return prm->v;
	}
}

myencfs_error_entry
 _myencfs_error_entry_prm_add_u32(
	const myencfs_error_entry entry,
	const int k,
	const uint32_t u32
) {
	myencfs_variant *v;

	if (entry == NULL) {
		return NULL;
	}

	if ((v = _myencfs_error_entry_prm_new_variant(entry, k)) != NULL) {
		v->t = myencfs_variant_type_u32;
		v->d->u32 = u32;
	}

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_prm_add_u64(
	const myencfs_error_entry entry,
	const int k,
	const uint32_t u64
) {
	myencfs_variant *v;

	if (entry == NULL) {
		return NULL;
	}

	if ((v = _myencfs_error_entry_prm_new_variant(entry, k)) != NULL) {
		v->t = myencfs_variant_type_u64;
		v->d->u64 = u64;
	}

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_prm_add_str(
	const myencfs_error_entry entry,
	const int k,
	const char * const str
) {
	myencfs_variant *v;

	if (entry == NULL) {
		return NULL;
	}

	if ((v = _myencfs_error_entry_prm_new_variant(entry, k)) != NULL) {
		v->t = myencfs_variant_type_str;
		strncpy(v->d->str, str, sizeof(v->d->str) - 1);
	}

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_prm_add_blob(
	const myencfs_error_entry entry,
	const int k,
	const unsigned char * const d,
	const size_t s
) {
	myencfs_variant *v;

	if (entry == NULL) {
		return NULL;
	}

	if ((v = _myencfs_error_entry_prm_new_variant(entry, k)) != NULL) {
		v->t = myencfs_variant_type_blob;
		v->d->blob->s = s < sizeof(v->d->blob->d) ? s : sizeof(v->d->blob->d);
		memcpy(v->d->blob->d, d, v->d->blob->s = s);
	}

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_vsprintf(
	const myencfs_error_entry entry,
	const int k,
	const char * const format,
	va_list ap
) {
	myencfs_variant *v;

	if ((v = _myencfs_error_entry_prm_new_variant(entry, k)) != NULL) {
		v->t = myencfs_variant_type_str;
		vsnprintf(v->d->str, sizeof(v->d->str), format, ap);
	}

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_sprintf(
	const myencfs_error_entry entry,
	const int k,
	const char * const format,
	...
) {
	myencfs_error_entry ret;
	va_list ap;

	va_start(ap, format);
	ret = _myencfs_error_entry_vsprintf(entry, k, format, ap);
	va_end(ap);

	return ret;
}

myencfs_error_entry
_myencfs_error_capture_indirect(
	const myencfs_error error,
	const char * const file,
	const int line,
	const char * const func
) {
	myencfs_error_entry entry = _myencfs_error_entry_new(error);

	if (error == NULL) {
		return NULL;
	}

	_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_SOURCE_FILE, file);
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_SOURCE_LINE, line);
	_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_SOURCE_FUNC, func);

	return entry;
}

myencfs_error_entry
_myencfs_error_entry_base(
	const myencfs_error_entry entry,
	const char * const hint,
	const uint32_t code,
	const bool authoritative,
	const char * const format,
	...
) {
	if (entry == NULL) {
		return NULL;
	}

	_myencfs_error_entry_prm_add_str(entry, MYENCFS_ERROR_KEY_HINT, hint);
	_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_CODE, code);

	if (authoritative) {
		_myencfs_error_entry_prm_add_u32(entry, MYENCFS_ERROR_KEY_AUTHORITATIVE, true);
	}

	if (format != NULL) {
		va_list ap;
		va_start(ap, format);
		_myencfs_error_entry_vsprintf(entry, MYENCFS_ERROR_KEY_DESCRIPTION, format, ap);
		va_end(ap);
	}

	return entry;
}
