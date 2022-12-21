#!/bin/bash

export RA_TYPE=123

if [ "${RA_TYPE}" == "epid" ]; then
    if [ "${ra_client_spid}" != "" ] && [ "${ra_client_key}" != "" ]; \
    then \
        make check_epid RA_TYPE=epid RA_CLIENT_SPID=${ra_client_spid} \
            RA_TLS_EPID_API_KEY=${ra_client_key} RA_CLIENT_LINKABLE=0; \
        make check_epid_fail RA_TYPE=epid RA_CLIENT_SPID=${ra_client_spid} \
            RA_TLS_EPID_API_KEY=${ra_client_key} RA_CLIENT_LINKABLE=0; \
    else \
        echo "Failure: no ra_client_spid and/or ra_client_key!"; \
        exit 1; \
    fi
elif [ "${RA_TYPE}" == "dcap" ]; then
    make check_dcap RA_TYPE=dcap;
    make check_dcap_fail RA_TYPE=dcap;
else
    echo "Invalid RA_TYPE env varible: ${RA_TYPE}";
    exit 1;
fi
