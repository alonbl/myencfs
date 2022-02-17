# myencfs Installation

POSIX and Windows (using mingw-w64) are supported.

## Dependencies

### Standard Dependnecies

* `pkg-config` complaint
* One of:
  * `=openssl-1.1`
  * `>=mbed-2` `MBEDTLS_PLATFORM_MEMORY`
  * `=wolfssl-5.x` --enable-aesgcm-stream
  * `bcrypt` (windows) builtin
* Optional
  * `>=libfuse-3`

### Test Dependencies

* Optional
  * `valgrind`
  * `>=fuse3`

### Checkout Dependncies

* autoconf
* automake
* libtool

Run:

```
$ autoreconf -ivf
```

## Development

Use `conf-dev.sh` to configure all features during development.

Use `MYENCFS_DO_VALGRIND=1 make check` to check using `valgrind`.

## Packaging

### Debian

#### Dependencies

##### Install

```
$ sudo apt install build-essential devscripts equivs
$ sudo mk-build-deps -i
```

##### Remove

```
$ sudo apt remove myencfs-build-deps
```

#### Build

```
$ debuild -b -uc -us -i
```

#### Release

Due to `deb` magics, before release version must be updated manually in `debian/changelog`.

#### Install Manually

```
$ dpkg -i myencfs*.deb
```

### RPM build

#### Dependencies

##### Install

```
$ sudo yum install rpm-build
$ sudo dnf build-dep myencfs.spec
```

#### Build

```
$ make dist
$ rpmbuild -tb myencfs-*.tar.bz2
```

#### Install Manually

```
$ rpm -i <rpm>
```

### Gentoo

Setup `myenc` repository using `/etc/portage/repos.conf/myencfs-repos.conf`:

```ini
[myencfs]
location = /var/db/repos/myencfs
```

Copy `gentoo` directory to `/var/db/repos/myencfs`.
