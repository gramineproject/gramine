#!/bin/sh

set -e

BUILDDIR=build-dist

rm -rf "$BUILDDIR"
# it doesn't matter what options we have here, this is only for meson dist
meson setup "$BUILDDIR" -Dskeleton=enabled -Dlibgomp=enabled >&2
meson dist -C "$BUILDDIR" --no-test --include-subprojects --formats=gztar >&2

tarball=$(meson introspect --projectinfo "$BUILDDIR" | jq -r '.descriptive_name + "-" + .version').tar.gz
tarball_orig=$(meson introspect --projectinfo "$BUILDDIR" | jq -r '.descriptive_name + "_" + .version | sub("-"; "~")').orig.tar.gz

# sanity check
(
    cd "$BUILDDIR"/meson-dist
    sha256sum -c "$tarball".sha256sum
) >&2

cp "$BUILDDIR"/meson-dist/"$tarball" "$tarball"
cp "$BUILDDIR"/meson-dist/"$tarball" "$tarball_orig"
printf %s\\n "$tarball_orig"
