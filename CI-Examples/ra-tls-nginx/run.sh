#!/bin/sh

set -e

gramine-sgx nginx &
pid=$!

sleep 10

test "$(curl --insecure -s https://localhost:8000/)" = "$(cat html/index.html)"
ret=$?

# verify that SIGTERM terminates nginx with all its sub-processes
kill $pid
sleep 1

if test -f /proc/$pid/exe
then
    echo "Gramine nginx server (PID=$pid) is still running"
    echo FAIL
    exit 1
fi

if test $ret -eq 0
then
    echo OK
else
    echo FAIL
fi

exit $ret
