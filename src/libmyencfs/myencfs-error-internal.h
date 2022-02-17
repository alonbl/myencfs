#ifndef __MYENCFS_ERROR_INTERNAL_H
#define __MYENCFS_ERROR_INTERNAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <myencfs/myencfs-error.h>
#include <myencfs/myencfs-system.h>

void
_myencfs_error_register_key_desc(
	struct myencfs_error_desc_s * const _desc,
	const size_t n
);

myencfs_error
_myencfs_error_new(
	const myencfs_system system
);

bool
_myencfs_error_construct(
	const myencfs_error error
);

bool
_myencfs_error_destruct(
	const myencfs_error error
);

myencfs_error_entry
_myencfs_error_entry_new(
	const myencfs_error error
);

void
_myencfs_error_entry_dispatch(
	const myencfs_error_entry entry
);

myencfs_variant *
_myencfs_error_entry_prm_new_variant(
	const myencfs_error_entry entry,
	const int k
);

myencfs_error_entry
_myencfs_error_entry_prm_add_u32(
	const myencfs_error_entry entry,
	const int k,
	const uint32_t u32
);

myencfs_error_entry
_myencfs_error_entry_prm_add_u64(
	const myencfs_error_entry entry,
	const int k,
	const uint32_t u64
);

myencfs_error_entry
_myencfs_error_entry_prm_add_str(
	const myencfs_error_entry entry,
	const int k,
	const char * const str
);

myencfs_error_entry
_myencfs_error_entry_prm_add_blob(
	const myencfs_error_entry entry,
	const int k,
	const unsigned char * const d,
	const size_t s
);

myencfs_error_entry
_myencfs_error_entry_vsprintf(
	const myencfs_error_entry entry,
	const int k,
	const char * const format,
	va_list ap
);

myencfs_error_entry
_myencfs_error_entry_sprintf(
	const myencfs_error_entry entry,
	const int k,
	const char * const format,
	...
) __attribute__((format(printf, 3, 4)));

myencfs_error_entry
_myencfs_error_capture_indirect(
	const myencfs_error error,
	const char * const file,
	const int line,
	const char * const func
);
#define _myencfs_error_capture(error) \
	_myencfs_error_capture_indirect((error), __FILE__, __LINE__, __func__)

myencfs_error_entry
_myencfs_error_entry_base(
	const myencfs_error_entry entry,
	const char * const hint,
	const uint32_t code,
	const bool authoritative,
	const char * const format,
	...
) __attribute__((format(printf, 5, 6)));

#endif
