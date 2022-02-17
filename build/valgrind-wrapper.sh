#!/bin/sh

srcdir="${srcdir:-.}"
MYENCFS_TOOL="${MYENCFS_TOOL:-myencfs-tool}"
VALGRIND="${VALGRIND:-valgrind}"
LIBTOOL="${LIBTOOL:-libtool}"

VALGRIND_CMD="${VALGRIND_CMD:-"${LIBTOOL}" --mode=execute ${VALGRIND}}"

if [ "${MYENCFS_DO_VALGRIND}" = 1 ]; then
	exec ${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all "$@"
else
	exec "$@"
fi
