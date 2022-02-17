#!/bin/sh
exec docker run -v /tmp:/tmp -u $(id -u) myencfs-fedora:ci "${@}"
