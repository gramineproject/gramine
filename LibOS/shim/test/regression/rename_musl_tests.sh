#!/bin/sh

set -e

DEST_DIR="$1"
shift 1

mkdir -p ${DEST_DIR}

for file in "$@"
do
    bn=`basename "${file}"`
    mv "${file}" "${DEST_DIR}/${bn#musl_}"
done
