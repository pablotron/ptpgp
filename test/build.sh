#!/bin/sh

INC="-I../include -DPTPGP_DEBUG -O2"
# INC=-I../include
TESTS="stream error armor base64"

cd ../src
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

cd ../test
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

for i in $TESTS; do
  cc -o ./$i{,.o} test-common.o ../src/*.o
done
