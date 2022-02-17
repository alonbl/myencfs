SUMMARY = "myencfs example application"
DESCRIPTION = "A simple directory encryption/decryption using authenticated encryption"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://COPYING;md5=9859f02baa869af387514f9e5dd8cc3e"

SRC_URI = "git://github.com/alonbl/myencfs.git;protocol=https"

SRCREV = "${AUTOREV}"
S = "${WORKDIR}/git"

inherit autotools pkgconfig

PACKAGECONFIG[bio-file] = " \
	--enable-bio-file, \
	--disable-bio-file \
"
PACKAGECONFIG[encrypt] = " \
	--enable-encrypt, \
	--disable-encrypt \
"
PACKAGECONFIG[decrypt] = " \
	--enable-decrypt, \
	--disable-decrypt \
"
PACKAGECONFIG[static-libs] = " \
	--enable-static, \
	--disable-static \
"
PACKAGECONFIG[crypto_openssl] = " \
	--with-crypto=openssl, \
	, \
	openssl, \
	openssl, \
	, \
	crypto_mbedtls crypto_wolfssl \
"
PACKAGECONFIG[crypto_mbedtls] = " \
	--with-crypto=mbedtls, \
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
PACKAGECONFIG[tools] = " \
	--enable-tool --enable-bio-file, \
	--disable-tool \
"
PACKAGECONFIG[fuse] = " \
	--enable-fuse --enable-decrypt --enable-bio-file, \
	--disable-fuse, \
	fuse3, \
	fuse3 \
"
EXTRA_OECONF += " \
	--with-build-id=${PF} \
"
