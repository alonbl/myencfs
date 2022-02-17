AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [0])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_VERSION_REVISION], [0])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([myencfs], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([include/myencfs/myencfs.h])
AM_INIT_AUTOMAKE

MYENCFS_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
MYENCFS_VERSION_MINOR="PACKAGE_VERSION_MINOR"
MYENCFS_VERSION_FIX="PACKAGE_VERSION_FIX"
MYENCFS_VERSION_REVISION="PACKAGE_VERSION_REVISION"

AC_SUBST([MYENCFS_VERSION_MAJOR])
AC_SUBST([MYENCFS_VERSION_MINOR])
AC_SUBST([MYENCFS_VERSION_FIX])
AC_SUBST([MYENCFS_VERSION_REVISION])

LIBMYENCFS_LT_CURRENT="1"
LIBMYENCFS_LT_OLDEST="1"
LIBMYENCFS_LT_REVISION="0"
LIBMYENCFS_LT_AGE="$((${LIBMYENCFS_LT_CURRENT}-${LIBMYENCFS_LT_OLDEST}))"

AC_CANONICAL_HOST

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[all-static],
	[AS_HELP_STRING([--enable-all-static], [enable all static mode])],
	,
	[enable_all_static="no"]
)

AC_ARG_ENABLE(
	[system-driver-default],
	[AS_HELP_STRING([--disable-system-driver-default], [disable default system driver])],
	,
	[enable_system_driver_default="yes"]
)

AC_ARG_ENABLE(
	[tests],
	[AS_HELP_STRING([--enable-tests], [enable tests])],
	,
	[enable_tests="no"]
)

AC_ARG_ENABLE(
	[tool],
	[AS_HELP_STRING([--enable-tool], [enable tool])],
	,
	[enable_tool="no"]
)

AC_ARG_ENABLE(
	[encrypt],
	[AS_HELP_STRING([--enable-encrypt], [enable encryption])],
	,
	[enable_encrypt="no"]
)

AC_ARG_ENABLE(
	[decrypt],
	[AS_HELP_STRING([--enable-decrypt], [enable decryption])],
	,
	[enable_decrypt="no"]
)

AC_ARG_ENABLE(
	[fuse],
	[AS_HELP_STRING([--enable-fuse], [enable fuse implementation])],
	,
	[enable_fuse="no"]
)

AC_ARG_ENABLE(
	[bio-file],
	[AS_HELP_STRING([--enable-bio-file], [enable file bio implementation])],
	,
	[enable_bio_file="no"]
)

AC_ARG_WITH(
	[crypto],
	[AS_HELP_STRING([--with-crypto=default|openssl|wolfssl|mbed|bcrypt], [cryptography library to use @<:@default=windows: bcrypt, posix: openssl@:>@])],
	,
	[with_crypto="default"]
)

AC_ARG_WITH(
	[build-id],
	[AS_HELP_STRING([--with-build-id=STR], [use this as build identifier])],
	,
	[with_build_id=""]
)
AC_ARG_WITH(
	[md-suffix],
	[AS_HELP_STRING([--with-md-suffix=STR], [use this suffix as netadata file suffix @<:@default=.myencfs@:>@])],
	,
	[with_md_suffix=".myencfs"]
)

AC_PROG_CC_C99
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
LT_INIT([win32-dll])
LT_LANG([Windows Resource])

AC_CHECK_FUNCS([ \
	getopt_long \
])

AC_MSG_CHECKING([Checking C99 vararg macros])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[
			#define test(x, ...) xxx(x __VA_OPT__(,) __VA_ARGS__)
			void xxx(int, ...);
		]],
		[[
			test(1);
		]]
	)],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_C99_VARARGS_MACROS], [1], [Have C99 varargs macros])
	],
	[
		AC_MSG_RESULT([no])
		AC_MSG_CHECKING([Checking GCC vararg macros])
		AC_COMPILE_IFELSE(
			[AC_LANG_PROGRAM(
				[[
					#define test(x, ...) xxx(x, ##__VA_ARGS__)
					void xxx(int, ...);
				]],
				[[
					test(1);
				]]
			)],
			[
				AC_MSG_RESULT([yes])
				AC_DEFINE([HAVE_GCC_VARARGS_MACROS], [1], [Have GCC varags macros])
			],
			[AC_MSG_ERROR([cannot find supported varargs macros])]
		)
	]
)

AC_ARG_VAR([MBEDCRYPTO_CFLAGS], [C compiler flags for MBEDCRYPTO])
AC_ARG_VAR([MBEDCRYPTO_LIBS], [linker flags for MBEDCRYPTO, overriding detection])
if test "${with_crypto}" = "default"; then
	case "${host}" in
		*-mingw*)
			with_crypto="bcrypt"
			;;
		*)
			with_crypto="openssl"
			;;
	esac
fi
case "${with_crypto}" in
	openssl)
		if test "${enable_all_static}" = "yes"; then
			ifdef(
				[PKG_CHECK_MODULES_STATIC],
				[PKG_CHECK_MODULES_STATIC(
					[OPENSSLCRYPTO],
					[libcrypto >= 1.1.0],
					,
					[AC_MSG_ERROR([Cannot locate openssl libcrypto])]
				)],
				[
					# Old pkg.m4 hack
					saved_PKG_CONFIG="${PKG_CONFIG}"
					PKG_CONFIG="${PKG_CONFIG} --static"
					PKG_CHECK_MODULES(
						[OPENSSLCRYPTO],
						[libcrypto >= 1.1.0],
						,
						[AC_MSG_ERROR([Cannot locate openssl libcrypto])]
					)
					PKG_CONFIG="${saved_PKG_CONFIG}"
				]
			)
			# Fix segmentation error per pthread_setspecific is linked but pthread_mutex_lock is not
			if echo "${OPENSSLCRYPTO_LIBS}" | grep -q pthread; then
				LDFLAGS="${LDFLAGS} -Wl,-u,pthread_mutex_lock -Wl,-u,pthread_mutex_unlock"
			fi
		else
			PKG_CHECK_MODULES(
				[OPENSSLCRYPTO],
				[libcrypto >= 1.1.0],
				,
				[AC_MSG_ERROR([Cannot locate openssl libcrypto])]
			)
		fi

		CRYPTO_CFLAGS="${OPENSSLCRYPTO_CFLAGS}"
		CRYPTO_LIBS="${OPENSSLCRYPTO_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_OPENSSL], [1], [Enable openssl crypto])
	;;
	mbed)
		if test -z "${MBEDCRYPTO_LIBS}"; then
			AC_CHECK_LIB(
				[mbedcrypto],
				[mbedtls_gcm_init],
				[MBEDCRYPTO_LIBS="-lmbedcrypto"],
				[AC_MSG_ERROR([Cannot locate libmbedcrypto])]
			)
		fi
		CRYPTO_CFLAGS="${MBEDCRYPTO_CFLAGS}"
		CRYPTO_LIBS="${MBEDCRYPTO_LIBS}"

		old_CFLAGS="${CFLAGS}"
		old_LIBS="${LIBS}"
		CFLAGS="${CFLAGS} ${CRYPTO_CFLAGS}"
		LIBS="${LIBS} ${CRYPTO_LIBS}"
		AC_CHECK_FUNC(
			[mbedtls_platform_set_calloc_free],
			[AC_DEFINE([HAVE_MBEDTLS_PLATFORM_SET_CALLOC_FREE], [1], [We have mbedtls_platform_set_calloc_free])],
			[AC_MSG_WARN([MBEDTLS_PLATFORM_MEMORY is required for mbedtls memory integration])]
		)
		CFLAGS="${old_CFLAGS}"
		LIBS="${old_LIBS}"

		AC_DEFINE([ENABLE_CRYPTO_MBED], [1], [Enable mbed crypto])
	;;
	wolfssl)
		PKG_CHECK_MODULES(
			[WOLFSSL],
			[wolfssl >= 5],
			,
			[AC_MSG_ERROR([Cannot locate wolfssl])]
		)
		CRYPTO_CFLAGS="${WOLFSSL_CFLAGS}"
		CRYPTO_LIBS="${WOLFSSL_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_WOLFSSL], [1], [Enable wolfssl crypto])
	;;
	bcrypt)
		CRYPTO_CFLAGS=
		CRYPTO_LIBS="-lbcrypt"
		AC_DEFINE([ENABLE_CRYPTO_BCRYPT], [1], [Enable bcrypt crypto])
	;;
	*)
		AC_MSG_ERROR([Unsupported crypto '${with_crypto}'])
	;;
esac
AC_MSG_NOTICE([crypto engine: ${with_crypto}])
AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])

if test "${enable_fuse}" = "yes"; then
	PKG_CHECK_MODULES(
		[FUSE],
		[fuse3],
		[ac_av_fuse_version=32],
		[PKG_CHECK_MODULES(
			[FUSE],
			[fuse3x],
			[ac_av_fuse_version=32],
			[AC_MSG_ERROR([fuse is required])]
		)]
	)
	AC_DEFINE_UNQUOTED([FUSE_USE_VERSION], [${ac_av_fuse_version}], [FUSE version])
fi

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -pedantic -D_ISOC99_SOURCE -D_DEFAULT_SOURCE"
fi

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi

AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_HEADERS([ \
	endian.h \
])

AC_CHECK_FUNCS([ \
	explicit_bzero \
])

case "${host}" in
	*-mingw*)
		BUILD_WINDOWS=yes
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		AC_DEFINE([BUILD_WINDOWS], [1], [Build windows])

		AC_DEFINE_UNQUOTED([_MYENCFS_PATH_SEPARTOR], ['\\\\'], [Path separator])

		# Assume little endian
		AC_DEFINE([htole64(x)], [(x)], [htole64])
		AC_DEFINE([htole32(x)], [(x)], [htole32])
		AC_DEFINE([le64toh(x)], [(x)], [le64toh])
		AC_DEFINE([le32toh(x)], [(x)], [le32toh])
		AC_DEFINE([strerror_r(n, b, s)], [strerror_s((b), (s), (n))], [strerror_r])
		AC_DEFINE([HAVE_SECUREZEROMEMORY], [1], [Have SecureZeroMemory])
		;;
	*)
		AC_DEFINE_UNQUOTED([_MYENCFS_PATH_SEPARTOR], ['/'], [Path separator])
		;;
esac

AC_PROG_AWK
AC_ARG_VAR([VALGRIND], [path to valgrind utility])
AC_PATH_PROGS([VALGRIND], [valgrind])
AC_ARG_VAR([FUSERMOUNT], [path to fusermount module])
AC_PATH_PROGS([FUSERMOUNT], [fusermount3])
AC_PATH_PROGS([FUSERMOUNT], [fusermount])

test "${enable_all_static}" = "yes" && \
	LDFLAGS="${LDFLAGS} -all-static"

test "${enable_system_driver_default}" = "yes" && AC_DEFINE([ENABLE_SYSTEM_DRIVER_DEFAULT], [1], [Enable default system driver])
test "${enable_tool}" = "yes" && AC_DEFINE([ENABLE_TOOL], [1], [Enable tool])
test "${enable_fuse}" = "yes" && AC_DEFINE([ENABLE_FUSE], [1], [Enable fuse])
test "${enable_encrypt}" = "yes" && AC_DEFINE([ENABLE_ENCRYPT], [1], [Enable encryption])
test "${enable_decrypt}" = "yes" && AC_DEFINE([ENABLE_DECRYPT], [1], [Enable decryption])
test "${enable_bio_file}" = "yes" && AC_DEFINE([ENABLE_BIO_FILE], [1], [Enable decryption])


if test "${enable_tool}" = "yes"; then
	if test "${enable_encrypt}" = "yes" -o "${enable_decrypt}" = "yes"; then
		test "${enable_bio_file}" = "yes" || AC_MSG_ERROR([tool requires file bio for encrypt or decrypt])
	fi
fi
if test "${enable_fuse}" = "yes"; then
	test "${enable_decrypt}" = "yes" || AC_MSG_ERROR([fuse requires decrypt])
	test "${enable_bio_file}" = "yes" || AC_MSG_ERROR([fuse requires file bio])
fi

AC_DEFINE_UNQUOTED([_MYENCFS_MD_SUFFIX], ["${with_md_suffix}"], [Metadata file suffix])
AC_DEFINE_UNQUOTED([PACKAGE_BUILD_ID], ["${with_build_id}"], [Build identifier])

AC_DEFINE([_MYENCFS_MAX_LOW_LEVEL_CRYPTO_BUFFER_SIZE], [256], [Maximum low level crypto buffer size])
AC_DEFINE([_MYENCFS_IO_BLOCK_SIZE], [(10*1024)], [Buffer size for IO operations])
AC_DEFINE([_MYENCFS_DEFAULT_MAX_SIZE], [(1024*1024)], [Buffer size for IO operations])

pkgconfigdir="\$(libdir)/pkgconfig"
myencfsincludedir="\$(includedir)/myencfs"
AC_SUBST([pkgconfigdir])
AC_SUBST([myencfsincludedir])
AC_SUBST([LIBMYENCFS_LT_CURRENT])
AC_SUBST([LIBMYENCFS_LT_REVISION])
AC_SUBST([LIBMYENCFS_LT_AGE])
AC_SUBST([LIBMYENCFS_LT_OLDEST])
AC_SUBST([PACKAGE_BUILD_ID])
AM_CONDITIONAL([CROSS_COMPILING], [test "${cross_compiling}" = "yes"])
AM_CONDITIONAL([BUILD_WINDOWS], [test "${BUILD_WINDOWS}" = "yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "${enable_tests}" = "yes"])
AM_CONDITIONAL([ENABLE_TOOL], [test "${enable_tool}" = "yes"])
AM_CONDITIONAL([ENABLE_FUSE], [test "${enable_fuse}" = "yes"])
AM_CONDITIONAL([ENABLE_ENCRYPT], [test "${enable_encrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_DECRYPT], [test "${enable_decrypt}" = "yes"])
AM_CONDITIONAL([ENABLE_BIO_FILE], [test "${enable_bio_file}" = "yes"])
AM_CONDITIONAL([ENABLE_CRYPTO_OPENSSL], [test "${with_crypto}" = "openssl"])
AM_CONDITIONAL([ENABLE_CRYPTO_MBED], [test "${with_crypto}" = "mbed"])
AM_CONDITIONAL([ENABLE_CRYPTO_WOLFSSL], [test "${with_crypto}" = "wolfssl"])
AM_CONDITIONAL([ENABLE_CRYPTO_BCRYPT], [test "${with_crypto}" = "bcrypt"])

AC_CONFIG_FILES([
	Makefile
	build/Makefile
	debian/Makefile
	gentoo/Makefile
	include/Makefile
	include/myencfs/Makefile
	myencfs.spec
	src/Makefile
	src/libmyencfs/Makefile
	src/libmyencfs/libmyencfs.pc
	src/libmyencfs/versioninfo.rc
	src/myencfs-fuse/Makefile
	src/myencfs-tool/Makefile
	src/myencfs-tool/versioninfo.rc
	test/Makefile
	test/libmyencfs/Makefile
	test/myencfs-fuse/Makefile
	test/myencfs-tool/Makefile
])
AC_OUTPUT
