#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2024 Wojtek Porczyk <woju@invisiblethingslab.com>

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
        dch -b -v "$v" " "
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

    # python version spec forbids ~, it needs after last number "rcN" (without
    # a dot) or ".postN" (with a dot):
    # https://packaging.python.org/en/latest/specifications/version-specifiers/
    v_py=$(printf %s "$v" | sed -e 's/post~UNRELEASED/.post0/g' -e 's/~//g')

    if test -w pyproject.toml
    then
        echo patching pyproject.toml >&2
        sed -i -e "s/^\(version\s*=\).*$/version = \"$v_py\"/" pyproject.toml
        git add pyproject.toml
    fi

    if test -w graminescaffolding/__init__.py
    then
        echo patching graminescaffolding/__init__.py >&2
        sed -i -e "s/^\(__version__\s*=\).*$/__version__ = \"$v_py\"/" \
            graminescaffolding/__init__.py
        git add graminescaffolding/__init__.py
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
