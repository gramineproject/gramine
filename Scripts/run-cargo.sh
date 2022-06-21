#!/bin/sh

set -e

# The main issue this script needs to work around is that meson's custom_target doesn't
# like slashes in the output argument, so we need to move the output from cargo's `target`
# directory to where meson wants it.
#
# The alternative would be to use cargo's --out-dir option, however said option is currently
# unstable (see https://github.com/rust-lang/cargo/issues/6790).

# Moreover, we need to set up the settings normally controlled by the Cargo profile (debug vs release)
# in a way that makes sense with the more fine-grained control that Meson exposes
# in `meson configure`.

INPUT="$1"
OUTPUT="$2"
export CARGO_TARGET_DIR="$3"
DEBUG="$4"
OPTLEVEL="$5"
shift 5

# Rust doesn't understand opt-level=g.
if [ "$OPTLEVEL" = "g" ]; then
    OPTLEVEL=0
fi

export CARGO_PROFILE_MESON_OPT_LEVEL="$OPTLEVEL"
export CARGO_PROFILE_MESON_DEBUG="$DEBUG"

# We don't want bounds-checking for -Dbuildtype=debugoptimized.
if [ "$DEBUG" = "true" ] && [ "$OPTLEVEL" = 0 ]; then
    export CARGO_PROFILE_MESON_DEBUG_ASSERTIONS=true
    export CARGO_PROFILE_MESON_OVERFLOW_CHECKS=true
fi

# Unoptimized builds are more likely to be used for quick iteration, where incremental
# compilation will be useful.
if [ "$OPTLEVEL" = 0 ]; then
    export CARGO_PROFILE_MESON_INCREMENTAL=true
fi

cargo build --manifest-path "$INPUT" --profile "meson" "$@"
cp "$CARGO_TARGET_DIR/meson/$(basename "$OUTPUT")" "$OUTPUT"
cp "$CARGO_TARGET_DIR/meson/$(basename "$OUTPUT").d" "$OUTPUT.d"
