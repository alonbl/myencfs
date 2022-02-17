#ifndef __MYENCFS_VARIANT_H
#define __MYENCFS_VARIANT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum myencfs_variant_type_e {
	myencfs_variant_type_none,
	myencfs_variant_type_u32,
	myencfs_variant_type_u64,
	myencfs_variant_type_str,
	myencfs_variant_type_blob,
	__myencfs_variant_type_end
} myencfs_variant_type;

typedef struct myencfs_variant_s {
	myencfs_variant_type t;
	union {
		uint32_t u32;
		uint64_t u64;
		char str[1024];
		struct {
			unsigned char *d[1024 - sizeof(size_t)];
			size_t s;
		} blob[1];
	} d[1];
} myencfs_variant;

#ifdef __cplusplus
}
#endif

#endif
