#!/bin/sh

# Try to detect if compiler emitted SYSCALL instruction in an ELF file by
# disassembling. This is not foolproof, please only use for CI.

set -e

OBJDUMP="objdump -d -M intel-mnemonic"

while test $# -gt 0
do
    if $OBJDUMP --no-addresses --no-show-raw-insn "$1" | grep -q '^\s*syscall'
    then
        printf "ERROR: found syscall instruction in %s:\n" "$1"
        $OBJDUMP "$1" | grep -C20 syscall
        exit 1
    fi
    shift
done
