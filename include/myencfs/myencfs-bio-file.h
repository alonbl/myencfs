#ifndef __MYENCFS_BIO_FILE_H
#define __MYENCFS_BIO_FILE_H

#include <stdlib.h>
#include <stdbool.h>

#include <myencfs/myencfs-bio.h>

#ifdef __cplusplus
extern "C" {
#endif

myencfs_bio
myencfs_bio_file(
	const myencfs_context context,
	const char * const path,
	const char * const mode
);

#ifdef __cplusplus
}
#endif

#endif
