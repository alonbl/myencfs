#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <string.h>

#include <myencfs/myencfs-static.h>

static struct {
	bool init;
} __static_context[1];

void
_myencfs_error_static_init(void);

void
_myencfs_crypto_openssl_static_init(
	const myencfs_system system
);

void
_myencfs_crypto_openssl_static_clean(
	const myencfs_system system
);

void
_myencfs_crypto_mbed_static_init(
	const myencfs_system system
);

void
_myencfs_crypto_mbed_static_clean(
	const myencfs_system system
);

bool
myencfs_static_init(
	const myencfs_system system __attribute__((unused))
) {
	if (!__static_context->init) {
		_myencfs_error_static_init();
#if defined(ENABLE_CRYPTO_OPENSSL)
		_myencfs_crypto_openssl_static_init(system);
#endif
#if defined(ENABLE_CRYPTO_MBED)
		_myencfs_crypto_mbed_static_init(system);
#endif
		__static_context->init = true;
	}

	return true;
}

bool
myencfs_static_clean(
	const myencfs_system system __attribute__((unused))
) {
	if (__static_context->init) {
#if defined(ENABLE_CRYPTO_OPENSSL)
		_myencfs_crypto_openssl_static_clean(system);
#endif
#if defined(ENABLE_CRYPTO_MBED)
		_myencfs_crypto_mbed_static_clean(system);
#endif
		memset(__static_context, 0, sizeof(__static_context));
	}

	return true;
}
