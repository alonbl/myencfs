#!/bin/sh

srcdir="${srcdir:-.}"
FUSERMOUNT="${FUSERMOUNT:-fusermount}"
MYENCFS_FUSE="${MYENCFS_FUSE:-myencfs-fuse}"
MYENCFS_TOOL="${MYENCFS_TOOL:-myencfs-tool}"
LIBTOOL="${LIBTOOL:-libtool}"

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

test_sanity() {
	local PREFIX="${MYTMP}/sanity"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID1="keyid1"
	local KEY_ID2="keyid2"
	local BASE_PT="${PREFIX}/base-pt"
	local BASE_CT="${PREFIX}/base-ct"
	local LOG_FILE="${PREFIX}/log"
	local MNT="${PREFIX}/mnt"
	local FILES="file1.dat file2.dat file3.dat d/file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT}" "${BASE_PT}/d" "${BASE_CT}" "${MNT}"; do
		mkdir -p "${f}"
	done

	for f in "${KEY_ID1}" "${KEY_ID2}"; do
		dd if=/dev/urandom of="${KEY_STORE}/${f}" bs=1 count=$((256/8)) || die "Cannot generate '${f}'"
	done

	for f in ${FILES}; do
		dd if=/dev/urandom of="${BASE_PT}/${f}" bs=1 count=$((1024*50)) || die "Cannot generate '${f}'"

		"${MYENCFS_TOOL}" encrypt \
			--key-store="${KEY_STORE}" \
			--key-id="${KEY_ID1}" \
			--base-pt="${BASE_PT}" \
			--base-ct="${BASE_CT}" \
			--name="${f}" \
			|| die "Encrypt '${f}'"
	done

	dd if=/dev/urandom of="${BASE_PT}/file4.bad" bs=1 count=$((1024*50)) || die "dd failed"
	"${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID2}" \
		--base-pt="${BASE_PT}" \
		--base-ct="${BASE_CT}" \
		--name="file4.bad" \
		|| die "Encrypt file4.bad"

	rm "${KEY_STORE}/${KEY_ID2}"

	dd if=/dev/urandom of="${BASE_PT}/file5.missing" bs=1 count=$((1024*50)) || die "dd failed"

	"${MYENCFS_FUSE}" --log-file="${LOG_FILE}" --key-store="${KEY_STORE}" --base="${BASE_CT}" "${MNT}" \
		|| die "Cannot execute fuse"
	(
		_MNT="${MNT}"
		_LOG_FILE="${LOG_FILE}"
		cleanup1() {
			echo "### fuse log file:"
			echo "---"
			cat "${_LOG_FILE}"
			echo "---"

			sleep 2 # https://github.com/libfuse/libfuse/issues/647
			"${FUSERMOUNT}" -u "${_MNT}"
		}
		trap cleanup1 0

		ls -la "${MNT}"

		[ "$(ls "${MNT}" | wc -l)" -eq 5 ] || die "Wrong number of files"

		for f in ${FILES}; do
			cmp "${MNT}/${f}" "${BASE_PT}/${f}" || die "File '${f}' differs"
		done

		cat "${MNT}/file4.bad" > /dev/null && die "Should not be possible"

		true
	) || die "Failed"

	return 0
}

[ -x "${MYENCFS_TOOL}" ] || skip "no tool"
features="$("${MYENCFS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "verify feature is not available"
[ -x "${MYENCFS_FUSE}" ] || skip "no fuse"

MYTMP="$(mktemp -d)"
DATA="${MYTMP}/data"

TESTS="test_sanity"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
