#!/bin/sh

# includes/cflags
INC="-I../include -DPTPGP_DEBUG -O2"
# INC="-I../include -O2"

# libs
LIBS=""

# add gcrypt support
INC="$INC -DPTPGP_USE_GCRYPT $(libgcrypt-config --cflags)"
LIBS="$LIBS $(libgcrypt-config --libs)"

# list of tests to compile
TESTS="stream error armor base64 armor-encoder uri-parser gcrypt-hash"

cd ../src
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

cd ../test
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

for i in $TESTS; do
  cc -o ./$i{,.o} test-common.o ../src/*.o $LIBS
done
