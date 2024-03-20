#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2024 Wojtek Porczyk <woju@invisiblethingslab.com>

set -e

: ${D:="bookworm bullseye jammy focal"}

bump() {
    v="$1"
    test -n "$v"

    find . -name meson.build \( -path \*/subprojects/\* -o -print \) \
    | while read meson_build
    do
        printf 'patching %s\n' "$meson_build" >&2
        sed -i -e "s/^\(\s*version: '\).*\(',\)$/\1$v\2/" "$meson_build"
        git add "$meson_build"
    done

    echo patching debian/changelog >&2
    d="$D"
    case "$v" in
    *~UNRELEASED)
        d=UNRELEASED ;;
    *~*)
        d=$(printf %s "$d" | sed 's/\</unstable-/g') ;;
    esac
    if ! test "$(dpkg-parsechangelog -SVersion)" = "$v"
    then
        dch -b -v "$v" ""
    fi
    dch -r -D "$d" --force-distribution # this is interactive, will open editor
    git add debian/changelog

    if test -w gramine.spec
    then
        echo patching gramine.spec >&2
        sed -i -e "s/^\(Version: \).*$/\1$v/" gramine.spec
        git add gramine.spec
    fi

    if test -w packaging/alpine/APKBUILD
    then
        echo patching packaging/alpine/APKBUILD >&2
        sed -i -e "s/^\(_real_pkgver=\).*$/\1$v/" packaging/alpine/APKBUILD
        git add packaging/alpine/APKBUILD
    fi
}

commit() {
    v="$1"
    test -n "$v"
    shift

    git commit --signoff --message "Bump version to $v" "$@"
}


if test -z "$1"
then
    echo usage: "$0" VERSION >&2
    exit 2
fi
V="$1"
VP="${1%~*}"post~UNRELEASED

cd "$(git rev-parse --show-toplevel)"

bump "$V"

# to fix a mistake:
#   git reset --hard HEAD~
#   release.sh X.Y
case "$(git log -n1 --format=%s)" in
"Bump "*)   commit "$V" --amend ;;
*)          commit "$V" ;;
esac

bump "$VP"
commit "$VP"
