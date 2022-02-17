# myencfs Installation

POSIX and Windows (using mingw-w64) are supported.

## Dependencies

### Standard Dependencies

* `pkg-config` complaint
* One of:
  * `>=openssl-1.1`
  * `>=mbed-2` `MBEDTLS_PLATFORM_MEMORY`
  * `=wolfssl-5.x` --enable-aesgcm-stream
  * `bcrypt` (windows) builtin
* Optional
  * `>=libfuse-3`

### Test Dependencies

* Optional
  * `valgrind`
  * `>=fuse3`

### Checkout Dependencies

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

##### Prepare

```
$ ln -s packaging/debian
```

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

Due to `deb` magics, before release version must be updated manually in `packaging/debian/changelog`.

#### Install Manually

```
$ dpkg -i myencfs*.deb
```

### RPM build

#### Dependencies

##### Install

```
$ sudo yum install rpm-build
$ sudo dnf build-dep packaging/rpm/myencfs.spec
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

Copy `packaging/gentoo/myencfs` directory to `/var/db/repos/myencfs`.

### Yocto

#### Checkout

```
$ git clone git://git.yoctoproject.org/poky.git
$ git clone git clone git://git.openembedded.org/meta-openembedded
$ cd meta-openembedded
$ checkout honister
$ cd ../poky
$ checkout honister
```

#### Prepare

```
$ . oe-init-build-env
```

#### Configure

```
$ cat >> build/conf/bblayers.conf << __EOF__
YOCTOROOT = "${@os.path.abspath(os.path.join("${TOPDIR}", os.pardir))}"

BBLAYERS += " \
  ${YOCTOROOT}/../meta-openembedded/meta-oe \
  ${YOCTOROOT}/../meta-openembedded/meta-filesystems \
  ${YOCTOROOT}/../myencfs-root/myencfs/packaging/yocto/meta-myencfs \
  "
__EOF__
$ cat >> build/conf/local.conf << __EOF__
PACKAGECONFIG:append:pn-myencfs += " bio-file encrypt decrypt tools fuse crypto_openssl"
CORE_IMAGE_EXTRA_INSTALL += " myencfs"
__EOF__
```

#### Build

```
$ bitbake core-image-minimal
$ runqemu qemux86-64
```

### Buildroot

```
$ cd "${BR2_HOME}"
$ make BR2_EXTERNAL="${MYENCFS_HOME}/myencfs/packaging/buildroot/myencfs" menuconfig
$ make
```

### Windows NSIS

#### Dependencies

```
$ sudo apt install nsis
```

#### Build

```
$ ./configure --host=x86-w64-mingw32 --prefix=/ ...
$ make install DESTDIR="$(pwd)/tmp"
$ DESTDIR=tmp ./packaging/windows-nsis/build
```
