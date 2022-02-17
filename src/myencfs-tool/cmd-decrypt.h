#ifndef __CMD_DECRYPT_H
#define __CMD_DECRYPT_H

#include <myencfs/myencfs.h>

int
_cmd_info(
	const myencfs myencfs,
	int argc,
	char *argv[]
);

int
_cmd_verify(
	const myencfs myencfs,
	int argc,
	char *argv[]
);

int
_cmd_decrypt(
	const myencfs myencfs,
	int argc,
	char *argv[]
);

#endif
