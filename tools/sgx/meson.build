subdir('common')

subdir('is-sgx-available')
subdir('pf_crypt')
subdir('pf_tamper')

if epid or dcap
    subdir('quote-view')
    subdir('ra-tls')
endif

if epid
    subdir('ias-request')
    subdir('verify-ias-report')
endif
