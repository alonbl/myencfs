include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)
DISTCLEANFILES = \
	libmyencfs.pc \
	$(NULL)
CLEANFILES = \
	myencfs-all.exports \
	myencfs-all.exports.tmp \
	$(NULL)

MYENCFS_COMMON_EXPORTS = \
	myencfs-bio.exports \
	myencfs-context.exports \
	myencfs-error.exports \
	myencfs-static.exports \
	myencfs-system.exports \
	myencfs.exports \
	$(NULL)
MYENCFS_SELECTIVE_EXPORTS = \
	myencfs-bio-crypto-decrypt.exports \
	myencfs-bio-crypto-encrypt.exports \
	myencfs-bio-file.exports \
	myencfs-decrypt.exports \
	myencfs-encrypt.exports \
	$(NULL)

dist_noinst_DATA = \
	$(MYENCFS_COMMON_EXPORTS) \
	$(MYENCFS_SELECTIVE_EXPORTS) \
	$(NULL)

pkgconfig_DATA = libmyencfs.pc
noinst_LTLIBRARIES = libmyencfs-internal.la
lib_LTLIBRARIES = libmyencfs.la

AM_CFLAGS = \
	$(CRYPTO_CFLAGS) \
	$(NULL)
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

libmyencfs_internal_la_SOURCES = \
	myencfs-bio-crypto-internal.h \
	myencfs-bio-crypto-private.h \
	myencfs-bio-random.c \
	myencfs-bio-random.h \
	myencfs-bio-util.c \
	myencfs-bio-util.h \
	myencfs-bio.c \
	myencfs-context.c \
	myencfs-crypto.h \
	myencfs-error-internal.h \
	myencfs-error.c \
	myencfs-internal.h \
	myencfs-md.c \
	myencfs-md.h \
	myencfs-private.h \
	myencfs-static.c \
	myencfs-system.c \
	myencfs-util.c \
	myencfs-util.h \
	myencfs.c \
	$(NULL)
if ENABLE_CRYPTO_OPENSSL
libmyencfs_internal_la_SOURCES += \
	myencfs-crypto-openssl.c \
	$(NULL)
endif
if ENABLE_CRYPTO_MBED
libmyencfs_internal_la_SOURCES += \
	myencfs-crypto-mbedtls.c \
	$(NULL)
endif
if ENABLE_CRYPTO_WOLFSSL
libmyencfs_internal_la_SOURCES += \
	myencfs-crypto-wolfssl.c \
	$(NULL)
endif
if ENABLE_CRYPTO_BCRYPT
libmyencfs_internal_la_SOURCES += \
	myencfs-crypto-bcrypt.c \
	$(NULL)
endif
if ENABLE_BIO_FILE
libmyencfs_internal_la_SOURCES += \
	myencfs-bio-file.c \
	$(NULL)
endif
if ENABLE_ENCRYPT
libmyencfs_internal_la_SOURCES += \
	myencfs-encrypt.c \
	myencfs-bio-crypto-encrypt.c \
	$(NULL)
endif
if ENABLE_DECRYPT
libmyencfs_internal_la_SOURCES += \
	myencfs-decrypt.c \
	myencfs-bio-crypto-decrypt.c \
	$(NULL)
endif
libmyencfs_internal_la_LIBADD = \
	$(CRYPTO_LIBS) \
	$(NULL)

libmyencfs_la_DEPENDENCIES = \
	libmyencfs-internal.la \
	myencfs-all.exports \
	$(NULL)
if BUILD_WINDOWS
nodist_libmyencfs_la_SOURCES = \
	versioninfo.rc \
	$(NULL)
endif
libmyencfs_la_LIBADD = \
	libmyencfs-internal.la \
	$(NULL)
libmyencfs_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info @LIBMYENCFS_LT_CURRENT@:@LIBMYENCFS_LT_REVISION@:@LIBMYENCFS_LT_AGE@ \
	-export-symbols "myencfs-all.exports" \
	-no-undefined \
	$(NULL)

myencfs-all.exports: \
		$(MYENCFS_COMMON_EXPORTS) \
		$(MYENCFS_SELECTIVE_EXPORTS) \
		$(builddir)/Makefile \
		$(top_builddir)/config.h \
		$(NULL)
	rm -f myencfs-all.exports.tmp
	for f in $(MYENCFS_COMMON_EXPORTS); do \
		cat "$(srcdir)/$$f" >> myencfs-all.exports.tmp; \
	done
if ENABLE_ENCRYPT
	cat "$(srcdir)/myencfs-bio-crypto-encrypt.exports" >> myencfs-all.exports.tmp
	cat "$(srcdir)/myencfs-encrypt.exports" >> myencfs-all.exports.tmp
endif
if ENABLE_DECRYPT
	cat "$(srcdir)/myencfs-bio-crypto-decrypt.exports" >> myencfs-all.exports.tmp
	cat "$(srcdir)/myencfs-decrypt.exports" >> myencfs-all.exports.tmp
endif
if ENABLE_BIO_FILE
	cat "$(srcdir)/myencfs-bio-file.exports" >> myencfs-all.exports.tmp
endif
	mv myencfs-all.exports.tmp myencfs-all.exports

if BUILD_WINDOWS
mylibdir=$(libdir)
mylib_DATA=.libs/libmyencfs-@LIBMYENCFS_LT_OLDEST@.dll.def
.libs/libmyencfs-@LIBMYENCFS_LT_OLDEST@.dll.def:        libmyencfs.la
endif
