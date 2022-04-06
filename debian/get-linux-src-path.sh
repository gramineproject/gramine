#!/bin/sh

set -e

dir=$(dpkg-query -W linux-headers-\*-common | while read name version
do
    test -n "$version" || continue
    dpkg --compare-versions "$version" '>=' '5.11' || continue

    # sanity check: if directory does not exist, break here and not in meson
    dir=/usr/src/"$name"
    test -d "$dir" || exit 2

    printf %s\\n "$dir"
    break
done)

test -n "$dir" || exit 1
printf %s\\n "$dir"
