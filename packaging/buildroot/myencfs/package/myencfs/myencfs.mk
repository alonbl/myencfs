MYENCFS_VERSION = master
MYENCFS_SITE = $(call github,alonbl,myencfs,$(MYENCFS_VERSION))
MYENCFS_LICENSE = BSD3
MYENCFS_INSTALL_STAGING = YES
MYENCFS_DEPENDENCIES = host-pkgconf
MYENCFS_CONF_OPTS = --with-build-id=$(MYENCFS_VERSION)

ifeq ($(MYENCFS_VERSION), master)
MYENCFS_AUTORECONF = YES
endif

ifeq ($(BR2_PACKAGE_MYENCFS_CRYPTO_OPENSSL), y)
MYENCFS_DEPENDENCIES = openssl
MYENCFS_CONF_OPTS += --with-crypto=openssl
endif
ifeq ($(BR2_PACKAGE_MYENCFS_CRYPTO_MBEDTLS), y)
MYENCFS_DEPENDENCIES = mbedtls
MYENCFS_CONF_OPTS += --with-crypto=mbedtls
endif
ifeq ($(BR2_PACKAGE_MYENCFS_CRYPTO_WOLFSSL), y)
MYENCFS_DEPENDENCIES = wolfssl
MYENCFS_CONF_OPTS += --with-crypto=wolfssl
endif
ifeq ($(BR2_PACKAGE_MYENCFS_ENCRYPT), y)
MYENCFS_CONF_OPTS += --enable-encrypt
else
MYENCFS_CONF_OPTS += --disable-encrypt
endif
ifeq ($(BR2_PACKAGE_MYENCFS_DECRYPT), y)
MYENCFS_CONF_OPTS += --enable-decrypt
else
MYENCFS_CONF_OPTS += --disable-decrypt
endif
ifeq ($(BR2_PACKAGE_MYENCFS_BIO_FILE), y)
MYENCFS_CONF_OPTS += --enable-bio-file
else
MYENCFS_CONF_OPTS += --disable-bio-file
endif
ifeq ($(BR2_PACKAGE_MYENCFS_TOOLS), y)
MYENCFS_CONF_OPTS += --enable-tool
else
MYENCFS_CONF_OPTS += --disable-tool
endif
ifeq ($(BR2_PACKAGE_MYENCFS_FUSE), y)
MYENCFS_CONF_OPTS += --enable-fuse
else
MYENCFS_CONF_OPTS += --disable-fuse
endif

$(eval $(autotools-package))
