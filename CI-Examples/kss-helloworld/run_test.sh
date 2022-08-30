#!/usr/bin/env bash

set -e

# Default is SGX, because this test is SGX-specific
if test -n "$DIRECT"
then
    GRAMINE=gramine-direct
else
    GRAMINE=gramine-sgx
fi

echo Running kss-helloworld
$GRAMINE ./kss-helloworld > OUTPUT
grep -q 'isvprodid = 0005' OUTPUT && echo '[ Success 1/4 ]'
grep -q 'isvsvn = 2' OUTPUT && echo '[ Success 2/4 ]'
grep -q 'isvextprodid = cafef00dcafef00df00dcafef00dcafe' OUTPUT && echo '[ Success 3/4 ]'
grep -q 'isvfamilyid = 00112233445566778899aabbccddeeff' OUTPUT && echo '[ Success 4/4 ]'
rm OUTPUT
