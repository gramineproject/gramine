#!/bin/sh

# Try to detect if compiler emitted SYSCALL instruction in an ELF file by
# disassembling. This is not foolproof, please only use for CI.

set -e

# find only instructions, not <syscall[...]> symbols
PATTERN='^[0-9a-f:[:blank:]]*syscall'

while test $# -gt 0
do
    OBJDUMP=$(objdump -d -M intel-mnemonic "$1")
    if printf %s "$OBJDUMP" | grep -q -i "$PATTERN"
    then
        printf "ERROR: found syscall instruction in %s:\n" "$1"
        printf %s\\n "$OBJDUMP" | grep -C20 -i "$PATTERN"
        exit 1
    fi
    shift
done
