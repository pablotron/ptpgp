#!/bin/sh

INC="-I../include -DPTPGP_DEBUG"
# INC=-I../include
TESTS=stream error armor

cd ../src
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

cd ../test
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

for i in $TESTS; do
  cc -o ./$i{,.o} ../src/*.o
done
