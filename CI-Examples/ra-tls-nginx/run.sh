#!/bin/sh

set -e

gramine-sgx nginx &
pid=$!

sleep 10

test "$(curl --insecure -s https://localhost:8000/)" = "$(cat html/index.html)"
ret=$?

kill -9 $pid

if test $ret -eq 0
then
    echo OK
else
    echo FAIL
fi

exit $ret
