#!/bin/sh

srcdir="${srcdir:-.}"
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

doval() {
	if [ "${MYENCFS_DO_VALGRIND}" = 1 ]; then
		${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all "$@"
	else
		"$@"
	fi
}

test_sanity() {
	local PREFIX="${MYTMP}/sanity"
	local KEY_STORE="${PREFIX}/key-store"
	local KEY_ID="id1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local FILES="file1.dat file2.dat file3.dat d/file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT1}/d" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	for f in ${FILES}; do
		dd status=none if=/dev/urandom of="${BASE_PT1}/${f}" bs=1 count=$((1024*50)) || die "Cannot generate '${f}'"

		doval "${MYENCFS_TOOL}" encrypt \
			--key-store="${KEY_STORE}" \
			--key-id="${KEY_ID}" \
			--base-pt="${BASE_PT1}" \
			--base-ct="${BASE_CT}" \
			--name="${f}" \
			|| die "Encrypt '${f}'"
	done

	[ "$(doval "${MYENCFS_TOOL}" info --base-ct="${BASE_CT}" --name=file1.dat)" = "key-id: ${KEY_ID}" ] \
		|| die "Keyid is incorrect"

	for f in ${FILES}; do
		cmp "${BASE_PT1}/${f}" "${BASE_CT}/${f}" && die "File '${f}' is the same"
	done

	doval "${MYENCFS_TOOL}" verify \
		--key-store="${KEY_STORE}" \
		--base-ct="${BASE_CT}" \
		--name="${f}-111" \
		&& die "File does not exist should fail"

	for f in ${FILES}; do
		doval "${MYENCFS_TOOL}" verify \
			--key-store="${KEY_STORE}" \
			--base-ct="${BASE_CT}" \
			--name="${f}" \
			|| die "Verify '${f}'"

		doval "${MYENCFS_TOOL}" decrypt \
			--key-store="${KEY_STORE}" \
			--base-pt="${BASE_PT2}" \
			--base-ct="${BASE_CT}" \
			--name="${f}" \
			|| die "Decrypt '${f}'"

		cmp "${BASE_PT1}/${f}" "${BASE_PT2}/${f}" || die "File '${f}' differs"
	done

	return 0
}

test_bad_key() {
	local PREFIX="${MYTMP}/bad_key"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done

	dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT1}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		|| die "Encrypt"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" decrypt \
		--key-store="${KEY_STORE}" \
		--base-pt="${BASE_PT2}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		&& die "Decrypt succeeded but should fail"

	return 0
}

test_bad_content() {
	local PREFIX="${MYTMP}/bad_content"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done

	dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT1}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		|| die "Encrypt"

	dd status=none if=/dev/urandom of="${BASE_CT}/${NAME}" seek=5 bs=1 count=5 conv=notrunc || die "Cannot override file"

	doval "${MYENCFS_TOOL}" decrypt \
		--key-store="${KEY_STORE}" \
		--base-pt="${BASE_PT2}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		&& die "Decrypt succeeded but should fail"

	return 0
}

test_bad_size() {
	local PREFIX="${MYTMP}/bad_size"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done

	dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT1}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		|| die "Encrypt"

	printf "\x01" | dd status=none of="${BASE_CT}/${NAME}.myencfs" seek=8 bs=1 count=1 conv=notrunc || die "Cannot override file"

	doval "${MYENCFS_TOOL}" decrypt \
		--key-store="${KEY_STORE}" \
		--base-pt="${BASE_PT2}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		&& die "Decrypt succeeded but should fail"

	return 0
}

test_rename() {
	local PREFIX="${MYTMP}/rename"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat"
	local f

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done
	dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT1}" \
		--base-ct="${BASE_CT}" \
		--name="file1.dat" \
		|| die "Encrypt"

	mv "${BASE_CT}/${NAME}" "${BASE_CT}/${NAME}1" || die "Cannot move file"
	mv "${BASE_CT}/${NAME}.myencfs" "${BASE_CT}/${NAME}1.myencfs" || die "Cannot move file"

	doval "${MYENCFS_TOOL}" decrypt \
		--key-store="${KEY_STORE}" \
		--base-pt="${BASE_PT2}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}1" \
		&& die "Decrypt succeeded but should fail"

	return 0
}

test_bad_name() {
	local PREFIX="${MYTMP}/bad_name"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid1"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="../file1.dat"

	for f in "${KEY_STORE}" "${BASE_PT1}/x" "${BASE_CT}"; do
		mkdir -p "${f}"
	done
	dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}'"

	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	doval "${MYENCFS_TOOL}" encrypt \
		--key-store="${KEY_STORE}" \
		--key-id="${KEY_ID}" \
		--base-pt="${BASE_PT1}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}" \
		&& die "Should fail as name is invalid"

	return 0
}

test_file_size() {
	local PREFIX="${MYTMP}/file_size"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file1.dat."
	local f
	local i

	if [ "${MYENCFS_DO_VALGRIND}" = 1 ]; then
		echo skip
		return 0
	fi

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done
	dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}'"

	i=0
	while [ "${i}" -lt $((512/8)) ]; do
		dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}${i}" bs=1 count="${i}" || die "Cannot generate '${NAME}${i}"

		doval "${MYENCFS_TOOL}" encrypt \
			--key-store="${KEY_STORE}" \
			--key-id="${KEY_ID}" \
			--base-pt="${BASE_PT1}" \
			--base-ct="${BASE_CT}" \
			--name="${NAME}${i}" \
			|| die "Encrypt ${i}"

		i=$((${i}+1))
	done

	i=0
	while [ "${i}" -lt $((512/8)) ]; do
		doval "${MYENCFS_TOOL}" decrypt \
			--key-store="${KEY_STORE}" \
			--base-pt="${BASE_PT2}" \
			--base-ct="${BASE_CT}" \
			--name="${NAME}${i}" \
			|| die "Decrypt ${i}"

		i=$((${i}+1))
	done

	return 0
}

test_keystore() {
	local PREFIX="${MYTMP}/keystore"
	local KEY_STORE="${PREFIX}/keystore"
	local KEY_ID="keyid"
	local BASE_PT1="${PREFIX}/base-pt1"
	local BASE_PT2="${PREFIX}/base-pt2"
	local BASE_CT="${PREFIX}/base-ct"
	local NAME="file.dat"
	local f
	local i

	for f in "${KEY_STORE}" "${BASE_PT1}" "${BASE_PT2}" "${BASE_CT}"; do
		mkdir -p "${f}"
	done

	for i in 1 2 3 4; do
		dd status=none if=/dev/urandom of="${BASE_PT1}/${NAME}${i}" bs=1 count=$((1024*50)) || die "Cannot generate '${NAME}${i}"
		dd status=none if=/dev/urandom of="${KEY_STORE}/${KEY_ID}${i}" bs=1 count=$((256/8)) || die "Cannot generate '${KEY_ID}${i}'"

		doval "${MYENCFS_TOOL}" encrypt \
			--key-store="${KEY_STORE}" \
			--key-id="${KEY_ID}${i}" \
			--base-pt="${BASE_PT1}" \
			--base-ct="${BASE_CT}" \
			--name="${NAME}${i}" \
			|| die "Encrypt"
	done

	rm "${KEY_STORE}/${KEY_ID}4"

	for i in 1 2 3; do
		doval "${MYENCFS_TOOL}" decrypt \
			--key-store="${KEY_STORE}" \
			--base-pt="${BASE_PT2}" \
			--base-ct="${BASE_CT}" \
			--name="${NAME}${i}" \
			|| die "Decrypt failed for '${NAME}${i}'"
		cmp "${BASE_PT1}/${NAME}${i}" "${BASE_PT2}/${NAME}${i}" || die "Differs '${NAME}${i}'"
	done

	doval "${MYENCFS_TOOL}" decrypt \
		--key-store="${KEY_STORE}" \
		--base-pt="${BASE_PT2}" \
		--base-ct="${BASE_CT}" \
		--name="${NAME}4" \
		&& die "Decrypt succeeded but should fail"

	return 0
}

[ -x "${MYENCFS_TOOL}" ] || skip "no tool"
features="$("${MYENCFS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "encrypt feature is not available"
echo "${features}" | grep -q "decrypt" || skip "decrypt feature is not available"

MYTMP="$(mktemp -d)"
DATA="${MYTMP}/data"

TESTS="test_sanity test_bad_key test_bad_content test_bad_size test_rename test_bad_name test_file_size test_keystore"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done
