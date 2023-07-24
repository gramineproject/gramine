#!/bin/sh

set -e

gramine-sgx nginx &
pid=$!

sleep 10

test "$(curl --insecure -s https://localhost:8000/)" = "$(cat html/index.html)"
ret=$?

# wait till SIGTERM terminates nginx with all its sub-processes
kill $pid
while $(kill -0 $pid 2> /dev/null); do
    sleep 1
done

if test $ret -eq 0
then
    echo OK
else
    echo FAIL
fi

exit $ret
