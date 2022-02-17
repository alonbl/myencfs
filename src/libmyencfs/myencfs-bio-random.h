#ifndef __MYENCFS_BIO_RANDOM_H
#define __MYENCFS_BIO_RANDOM_H

#include <myencfs/myencfs-bio.h>

#include "myencfs-crypto.h"

myencfs_bio
_myencfs_bio_random(
	const myencfs_context context,
	const _myencfs_crypto crypto
);

#endif
