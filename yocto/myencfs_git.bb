SUMMARY = "myencfs example application"
DESCRIPTION="A simple directory encryption/decryption using authenticated encryption"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://COPYING;md5=9859f02baa869af387514f9e5dd8cc3e"

SRC_URI = "git://github.com/alonbl/myencfs.git;protocol=https"

SRCREV = "${AUTOREV}"
S = "${WORKDIR}/git"

inherit autotools pkgconfig

# MYENCFS_CRYPTO can be one, and only one, of [ crypto_openssl, crypto_mbedtls, crypto_wolfssl ]
MYENCFS_CRYPTO ?= "crypto_openssl"
# List of enabled features that can be overriden
PACKAGECONFIG ?= "tools encrypt decrypt bio-file fuse static-libs ${MYENCFS_CRYPTO}"

PACKAGECONFIG[tools]		= "--enable-tool -enable-bio-file, --disable-tool"
PACKAGECONFIG[encrypt]		= "--enable-encrypt,--disable-encrypt"
PACKAGECONFIG[decrypt]		= "--enable-decrypt, --disable-decrypt"
PACKAGECONFIG[bio-file]		= "--enable-bio-file, --disable-bio-file"
PACKAGECONFIG[static-libs]	= "--enable-static, --disable-static"
PACKAGECONFIG[crypto_openssl]	= " \
				--with-crypto=openssl, \
				, \
				openssl, \
				openssl, \
				, \
				crypto_mbedtls crypto_wolfssl \
				"

PACKAGECONFIG[crypto_mbedtls] = " \
				--with-crypto=mbed, \
				, \
				mbedtls, \
				mbedtls, \
				, \
				crypto_openssl crypto_wolfssl \
				"

PACKAGECONFIG[crypto_wolfssl] = " \
				--with-crypto=wolfssl, \
				, \
				wolfssl, \
				wolfssl, \
				, \
				crypto_openssl crypto_mbedtls \
				"

PACKAGECONFIG[fuse] = "--enable-fuse --enable-decrypt --enable-bio-file, \
				--disable-fuse, \
				fuse3, \
				fuse3 \
				"
