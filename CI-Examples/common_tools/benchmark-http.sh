#!/usr/bin/env bash

# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

# Run like: ./benchmark-http.sh host:port
#
# It also works with HTTPS, e.g., ./benchmark-http.sh https://localhost:8443

declare -A THROUGHPUTS
declare -A LATENCIES
LOOP=${LOOP:-1}
DOWNLOAD_HOST=$1
DOWNLOAD_FILE=${DOWNLOAD_FILE:-random/10K.1.html}
CONNECTIONS=${CONNECTIONS:-300}
DURATION=${DURATION:-30}
CONCURRENCY_LIST=${CONCURRENCY_LIST:-"1 2 4 8 16 32 64 128 256"}
RESULT=result-$(date +%y%m%d-%H%M%S)

# This parameter requires wrk2 tool installed for the wrk binary.
REQUESTS_OPT="${REQUESTS:+-R"$REQUESTS"}"

touch "$RESULT"
convert_throughput() {
    local THROUGHPUT_VAL=0
    local THROUGHPUT_UNIT=""
    if [[ "$1" =~ ^([0-9]*)(\.[0-9]*)?([kMG]?)$ ]]; then
        THROUGHPUT_VAL="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        THROUGHPUT_UNIT=${BASH_REMATCH[3]}
    fi

    if [ -z "$THROUGHPUT_UNIT" ]; then
        THROUGHPUT=$THROUGHPUT_VAL
    elif [ "$THROUGHPUT_UNIT" = "k" ]; then
        THROUGHPUT=$(python3 -c "print($THROUGHPUT_VAL * 1000)")
    elif [ "$THROUGHPUT_UNIT" = "M" ]; then
        THROUGHPUT=$(python3 -c "print($THROUGHPUT_VAL * 1000000)")
    elif [ "$THROUGHPUT_UNIT" = "G" ]; then
        THROUGHPUT=$(python3 -c "print($THROUGHPUT_VAL * 1000000000)")
    else
        THROUGHPUT=0
    fi

    echo "$THROUGHPUT"
}

latency_in_milliseconds() {
    local LATENCY_VAL=0
    local LATENCY_UNIT=""
    if [[ "$1" =~ ^([0-9]*)(\.[0-9]*)?(us|ms|s|m|h)?$ ]]; then
        LATENCY_VAL="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        LATENCY_UNIT=${BASH_REMATCH[3]}
    fi

    if [ -z "$LATENCY_UNIT" ] || [ "$LATENCY_UNIT" = "ms" ]; then
        LATENCY=$LATENCY_VAL
    elif [ "$LATENCY_UNIT" = "us" ]; then
        LATENCY=$(python3 -c "print($LATENCY_VAL / 1000)")
    elif [ "$LATENCY_UNIT" = "s" ]; then
        LATENCY=$(python3 -c "print($LATENCY_VAL * 1000)")
    elif [ "$LATENCY_UNIT" = "m" ]; then
        LATENCY=$(python3 -c "print($LATENCY_VAL * 1000 * 60)")
    elif [ "$LATENCY_UNIT" = "h" ]; then
        LATENCY=$(python3 -c "print($LATENCY_VAL * 1000 * 3600)")
    else
        LATENCY=0
    fi

    echo "$LATENCY"
}

RUN=0
while [ $RUN -lt "$LOOP" ]
do
    for CONCURRENCY in $CONCURRENCY_LIST
    do
        rm -f OUTPUT
        echo "wrk -c $CONNECTIONS -d $DURATION -t $CONCURRENCY $REQUESTS_OPT $DOWNLOAD_HOST/$DOWNLOAD_FILE"
        # shellcheck disable=SC2086
        wrk -c "$CONNECTIONS" -d "$DURATION" -t "$CONCURRENCY" $REQUESTS_OPT "$DOWNLOAD_HOST/$DOWNLOAD_FILE" > OUTPUT || exit $?

        THROUGHPUT_STR=$(grep -m1 "Req/Sec" OUTPUT | awk '{ print $2 }')
        THROUGHPUT=$(convert_throughput "$THROUGHPUT_STR")
        if [ "$THROUGHPUT" = "0" ]; then
            echo "Throughput is zero!"; exit 1;
        fi

        LATENCY_STR=$(grep -m1 "Latency" OUTPUT | awk '{ print $2 }')
        LATENCY=$(latency_in_milliseconds "$LATENCY_STR")
        if [ "$LATENCY" = "0" ]; then
            echo "Latency is zero!"; exit 1;
        fi

        if [ ${#THROUGHPUTS[$CONCURRENCY]} -eq 0 ] || [ ${#LATENCIES[$CONCURRENCY]} -eq 0 ]; then
            THROUGHPUTS[$CONCURRENCY]="$THROUGHPUT"
            LATENCIES[$CONCURRENCY]="$LATENCY"
        else
            THROUGHPUTS[$CONCURRENCY]="${THROUGHPUTS[$CONCURRENCY]} $THROUGHPUT"
            LATENCIES[$CONCURRENCY]="${LATENCIES[$CONCURRENCY]} $LATENCY"
        fi
        echo "Run = $((RUN+1)) Concurrency = $CONCURRENCY Per thread Throughput (req/sec) = $THROUGHPUT, Latency (ms) = $LATENCY"

    done
    (( RUN++ ))
done

for CONCURRENCY in $CONCURRENCY_LIST
do
    THROUGHPUT=$(echo "${THROUGHPUTS[$CONCURRENCY]}" | tr " " "\n" | sort -n | awk '{a[NR]=$0}END{if(NR%2==1)print a[(NR + 1)/2];else print (a[NR/2]+a[NR/2 + 1])/2}')
    LATENCY=$(echo "${LATENCIES[$CONCURRENCY]}" | tr " " "\n" | sort -n | awk '{a[NR]=$0}END{if(NR%2==1)print a[(NR + 1)/2];else print (a[NR/2]+a[NR/2 + 1])/2}')
    printf "Concurrency = %3d: Per Thread Median Througput (req/sec) = %9.3f, Latency (ms) = %9.3f\n" \
        "$CONCURRENCY" "$THROUGHPUT" "$LATENCY" | tee -a "$RESULT"
done

echo "Result file: $RESULT"
