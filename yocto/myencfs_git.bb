SUMMARY = "myencfs example application"
DESCRIPTION="A simple directory encryption/decryption using authenticated encryption"
LICENSE = "BSD"
LIC_FILES_CHKSUM = "file://COPYING;md5=9859f02baa869af387514f9e5dd8cc3e \
                    file://debian/copyright;md5=358aa3ad2f63e0c87d59d3150ef3fd7e"

SRC_URI = "git://github.com/alonbl/myencfs.git;protocol=https"

SRCREV = "${AUTOREV}"
S = "${WORKDIR}/git"

# Crypto can be either openssl_crypto or mbedtls_crypto
MYENCFS_CRYPTO ?= "openssl_crypto"
# List of enabled features that can be overriden
PACKAGECONFIG ?= "tools encrypt decrypt bio-file test fuse static-libs ${MYENCFS_CRYPTO}"


PACKAGECONFIG[tools]	= "--enable-tool"
PACKAGECONFIG[encrypt]	= "--enable-encrypt"
PACKAGECONFIG[decrypt]	= "--enable-decrypt"
PACKAGECONFIG[bio-file]	= "--enable-bio-file"
PACKAGECONFIG[test]	= "--enable-tests"
PACKAGECONFIG[static-libs]	= "--enable-all-static"
PACKAGECONFIG[openssl_crypto]	= " \
				--with-crypto=openssl, \
				, \
				openssl, \
				openssl, \
				, \
				mbedtls_crypto \
				"

PACKAGECONFIG[mbedtls_crypto] = " \
				--with-crypto=mbed, \
				, \
				mbedtls, \
				mbedtls, \
				, \
				openssl_crypto \
				"

PACKAGECONFIG[fuse] = "--enable-fuse --enable-decrypt --enable-bio-file, \
				, \
				fuse3, \
				fuse3 \
				"
