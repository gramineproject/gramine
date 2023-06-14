#!/bin/sh

# Usage:
#
#    encrypt_file file_to_encrypt file_encrypted
#
# Encrypts the file using `gramine-sgx-pf-crypt encrypt`.

set -e

SRC_FILE="$1"
DEST_FILE="$2"

# The hard-coded key must correspond to `fs.insecure__keys.default` in test manifests
# (e.g. in `helloworld_enc.manifest.template`). Note that POSIX printf doesn't understand hex so we
# must use octal.
WRAPKEY_FILE=$(mktemp /tmp/gramine-wrap-key.XXXXXX)
printf "\377\356\335\314\273\252\231\210" > ${WRAPKEY_FILE}
printf "\167\146\125\104\63\42\21\0"     >> ${WRAPKEY_FILE}

gramine-sgx-pf-crypt encrypt --input ${SRC_FILE} --output ${DEST_FILE} --wrap-key ${WRAPKEY_FILE}

# Copy mode bits from input file; required to e.g. mark the output file as executable (Gramine
# enforces the check for executable bit on entrypoint files).
chmod --reference=${SRC_FILE} ${DEST_FILE}

rm ${WRAPKEY_FILE}
