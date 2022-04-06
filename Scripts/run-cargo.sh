#!/bin/sh -e

# The main issue this script needs to work around is that meson's custom_target doesn't
# like slashes in the output argument, so we need to move the output from cargo's `target`
# directory to where meson wants it.
#
# The alternative would be to use cargo's --out-dir option, however said option is currently
# unstable (see https://github.com/rust-lang/cargo/issues/6790).

INPUT="$1"
OUTPUT="$2"
export CARGO_TARGET_DIR="$3"
BUILD_TYPE="$4"
shift 4

# For historical reasons, the profile that outputs to target/debug is called dev.
if [ "$BUILD_TYPE" = "debug" ]; then
    PROFILE="dev"
else
    PROFILE="$BUILD_TYPE"
fi

cargo build --manifest-path "$INPUT" --profile "$PROFILE" "$@"
cp "$CARGO_TARGET_DIR/$BUILD_TYPE/$(basename "$OUTPUT")" "$OUTPUT"
cp "$CARGO_TARGET_DIR/$BUILD_TYPE/$(basename "$OUTPUT").d" "$OUTPUT.d"
