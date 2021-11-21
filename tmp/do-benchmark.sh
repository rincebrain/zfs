#!/bin/bash

# use newly build zfs utils
export PATH="../bin:$PATH"

# 4GB pool in memory
#DISK="/dev/shm/testdisk.raw"
DISK="/tmp/testdisk.raw"
TDIR="/dev/shm/linux-5.11.13"

# name of testpool
POOL="testpool"

zpool destroy $POOL
sudo rm -f $DISK
dd if=/dev/zero of=$DISK bs=2G count=1
#truncate -s 2G $DISK
rm -rf /testpool

function load_testdir() {
  CWD=`pwd`

  URL="https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.13.tar.xz"
  FILE="linux-5.11.13.tar.xz"

  # ~200MB archiv
  test -f $FILE || wget $URL
  cd `dirname $TDIR`
  xzcat "$CWD/$FILE" | tar x
  cd $CWD
  test -d $TDIR || exit 111
}

# unpack oncy to memory
test -d $TDIR || load_testdir

function doit() {
  csum=$1

  zpool create -f -o ashift=12 \
  -O atime=off \
  -O canmount=off \
  -O dedup=$csum \
  $POOL $DISK

  zfs set compression=off $POOL
  zfs create $POOL/dedup
  for i in `seq 1 3`; do
    dir=/$POOL/dedup/$i
    mkdir -p $dir
    cp -r $TDIR $dir
    for i in `seq 1 10`; do
      zpool scrub -w $POOL
    done
  done
  sync
  zpool status -D $POOL
  zpool destroy $POOL
}

sync
echo 3 > /proc/sys/vm/drop_caches
time doit edonr,verify
echo "^ Edon-R"

sync
echo 3 > /proc/sys/vm/drop_caches
time doit sha256
echo "^ SHA256"

sync
echo 3 > /proc/sys/vm/drop_caches
time doit sha512
echo "^ SHA512/256"

sync
echo 3 > /proc/sys/vm/drop_caches
time doit skein
echo "^ Skein"

sync
echo 3 > /proc/sys/vm/drop_caches
time doit blake3
echo "^ BLAKE3"