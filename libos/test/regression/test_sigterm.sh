#!/bin/sh

set -e

rm -f tmp/shell_fifo
mkfifo tmp/shell_fifo

$@ 2>&1 >tmp/shell_fifo &
pid=$!

while read line; do
   case "$line" in
   *READY*)
      break
      ;;
   *)
      ;;
   esac
done <tmp/shell_fifo

kill -TERM $pid
wait $pid

echo "SHELL OK"
