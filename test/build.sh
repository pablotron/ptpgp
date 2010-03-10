#!/bin/sh

INC="-I../include -DPTPGP_DEBUG"
# INC=-I../include

cd ../src
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

cd ../test
for i in *.c; do
  c99 -c -W -Wall -O2 $INC $i
done

cc -o ./dump-stream{,.o} ../src/*.o
cc -o ./error{,.o} ../src/*.o
