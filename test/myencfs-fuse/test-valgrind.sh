#!/bin/sh

srcdir="${srcdir:-.}"
FUSERMOUNT="${FUSERMOUNT:-fusermount}"
MYENCFS_FUSE="${MYENCFS_FUSE:-myencfs-fuse}"
MYENCFS_TOOL="${MYENCFS_TOOL:-myencfs-tool}"
VALGRIND="${VALGRIND:-valgrind}"
LIBTOOL="${LIBTOOL:-libtool}"

VALGRIND_CMD="${VALGRIND_CMD:-"${LIBTOOL}" --mode=execute ${VALGRIND}}"

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

skip() {
	local m="$1"
	echo "SKIP: ${m}" >&2
	exit 77
}

MYTMP=
cleanup() {
	rm -fr "${MYTMP}"
}
trap cleanup 0

test_valgrind() {

	local PREFIX="${MYTMP}/valgrind"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT="${PREFIX}/base-pt"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat"
	local MNT="${PREFIX}/mnt"
	local f

	for f in "${KEY_STORE}" "${BASE_PT}" "${BASE_CT}" "${MNT}"; do
		mkdir -p "${f}"
	done

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	dd status=none if=/dev/urandom of="${BASE_PT}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	"${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		|| die "Encrypt '${NAME}'"

	${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all --suppressions="${srcdir}/fuse.valgrind.supp" \
		"${MYENCFS_FUSE}" -f --key-store="${KEY_STORE}" --base="${BASE_CT}" "${MNT}" &
	local pid=$!

	while true; do
		kill -0 "${pid}" || die "fuse died"
		[ "$(ls "${MNT}" | wc -l)" -ne 0 ] && break
		sleep 1
	done

	local fail=0
	cmp "${MNT}/${NAME}" "${BASE_PT}/${NAME}" || fail=1

	kill "${pid}"
	wait "${pid}"

	[ "${fail}" -eq 0 ] || die "File differs"

	return 0
}

[ "${MYENCFS_DO_VALGRIND}" = 1 ] || skip "valgrind test is disabled"

[ -x "${MYENCFS_TOOL}" ] || skip "no tool"
features="$("${MYENCFS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "verify feature is not available"
[ -x "${MYENCFS_FUSE}" ] || skip "no fuse"

MYTMP="$(mktemp -d)"
DATA="${MYTMP}/data"

TESTS="test_valgrind"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
