#!/bin/sh

# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

set -e

gramine-sgx nginx &
pid=$!

../../scripts/wait_for_server 60 localhost 8000

test "$(curl --insecure -s https://localhost:8000/)" = "$(cat html/index.html)"
ret=$?

kill $pid
wait $pid

if test $ret -eq 0
then
    echo OK
else
    echo FAIL
fi

exit $ret
