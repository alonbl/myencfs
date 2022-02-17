# myencfs

## Outline

A simple directory symmetric encryption/decryption using authenticated encryption.

The metadata are placed as a separated file.

The file name and size are used in authenticated data to protect against rename and truncate.

## Interfaces

### Tool

#### Common

```
Usage: myencfs-tool [options] command [options]
       --help
            this usage
       --version
            print version
       --verbose
            verbose diagnostics

Available commands:
        encrypt          - encrypt file
        info             - get file information
        verify           - verify file
        decrypt          - decrypt file
```

#### Encrypt

```
Usage: myencfs-tool [options] encrypt [options]
       --help
            this usage
       --key-store=DIRECTORY
            key store
       --key-id=STRING
            key id to use
       --base-pt=DIRECTORY
            plaintext directory base
       --base-ct=DIRECTORY
            ciphertext directory base
       --md-suffix=STRING
            metadata suffix
       --name=STRING
            plaintext file name
```

#### Info

```
Usage: myencfs-tool [options] info [options]
       --help
            this usage
       --base-ct=DIRECTORY
            ciphertext directory base
       --md-suffix=STRING
            metadata suffix
       --name=STRING
            ciphertext file name
```

#### Verify

```
Usage: myencfs-tool [options] verify [options]
       --help
            this usage
       --key-store=DIRECTORY
            key store
       --base-ct=DIRECTORY
            ciphertext directory base
       --md-suffix=STRING
            metadata suffix
       --max-size=NUMBER
            maximum file size
       --name=STRING
            ciphertext file name
```

#### Decrypt

```
Usage: myencfs-tool [options] decrypt [options]
       --help
            this usage
       --key-store=DIRECTORY
            key store
       --base-pt=DIRECTORY
            plaintext directory base
       --base-ct=DIRECTORY
            ciphertext directory base
       --md-suffix=STRING
            metadata suffix
       --max-size=NUMBER
            maximum file size
       --name=STRING
            ciphertext file name
```

#### Example

```sh
$ mkdir -p /tmp/myencfs/keystore /tmp/myencfs/base-pt1 /tmp/myencfs/base-ct /tmp/myencfs/base-pt2
$ dd if=/dev/urandom of=/tmp/myencfs/keystore/key1 bs=1 count=$((256/8))
$ dd if=/dev/urandom of=/tmp/myencfs/base-pt1/file1.dat bs=1M count=1
$ myencfs-tool encrypt --key-store=/tmp/myencfs/keystore --key-id=key1 --base-pt=/tmp/myencfs/base-pt1 --base-ct=/tmp/myencfs/base-ct --name=file1.dat || echo failed
$ myencfs-tool decrypt --key-store=/tmp/myencfs/keystore --base-pt=/tmp/myencfs/base-pt2 --base-ct=/tmp/myencfs/base-ct --name=file1.dat || echo failed
$ cmp /tmp/myencfs/base-pt1/file1.dat /tmp/myencfs/base-pt2/file1.dat
```

### C API

Refer to `include/myencfs`
* File based API
* BIO based API

Please review `myencfs-tool` as a reference implementation.

### Fuse interface

An overlay filesystem on top of the ciphertext directory.

```
usage: myencfs-fuse [options] <mountpoint>

<snip>

Options for myencfs-fuse:
    --log-level=N          log level (0-7)
    --log-file=FILE        log file
    --key-store=DIR        location of key store
    --base=DIR             location of ciphertext directory
    --md-suffix=SUFFIX     metadata suffix
    --max-size=N           maximum file size, default 1M

```

#### Caveats

* The fuse driver will load the entire file into memory when opened and hold it until close.

#### Example

```sh
$ mkdir /tmp/myencfs/mnt
$ myencfs-fuse --key-store=/tmp/myencfs/keystore --base=/tmp/myencfs/base-ct /tmp/myencfs/mnt
$ cmp /tmp/myencfs/mnt/file1.dat /tmp/myencfs/base-pt1/file1.dat
$ fusermount -u /tmp/myencfs/mnt
```
