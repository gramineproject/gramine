project('glibc', 'c', version: '2.38')

fs = import('fs')

glibc_output_paths = [
    'csu/crt1.o',
    'csu/crti.o',
    'csu/crtn.o',
    'dlfcn/libdl.so',
    'dlfcn/libdl.so.2',
    'libc.so',
    'libc.so.6',
    'login/libutil.so',
    'login/libutil.so.1',
    'math/libm.so',
    'math/libm.so.6',
    'nis/libnsl.so',
    'nis/libnsl.so.1',
    'nptl/libpthread.so',
    'nptl/libpthread.so.0',
    'nptl_db/libthread_db.so',
    'nptl_db/libthread_db.so.1',
    'nss/libnss_compat.so',
    'nss/libnss_compat.so.2',
    'nss/libnss_db.so',
    'nss/libnss_db.so.2',
    'nss/libnss_files.so',
    'nss/libnss_files.so.2',
    'resolv/libanl.so',
    'resolv/libanl.so.1',
    'resolv/libnss_dns.so',
    'resolv/libnss_dns.so.2',
    'resolv/libresolv.so',
    'resolv/libresolv.so.2',
    'rt/librt.so',
    'rt/librt.so.1',
]

if host_machine.cpu_family() == 'x86_64'
    glibc_output_paths += [
        'elf/ld-linux-x86-64.so.2',
        'elf/ld.so',
        'mathvec/libmvec.so',
        'mathvec/libmvec.so.1',
    ]
endif

glibc_output = []
foreach path : glibc_output_paths
    glibc_output += fs.name(path)
endforeach

extra_cflags = ''
if get_option('buildtype') == 'debug' or get_option('buildtype') == 'debugoptimized'
    extra_cflags += '-g'
endif

glibc = custom_target('glibc',
    command: [
        find_program('compile.sh'),
        host_machine.cpu_family(),
        '@CURRENT_SOURCE_DIR@',
        '@CURRENT_SOURCE_DIR@/glibc-2.38',
        meson.current_build_dir(),
        '@PRIVATE_DIR@',
        get_option('prefix'),
        get_option('libdir'),
        extra_cflags,
        glibc_output_paths,
    ],

    input: [
        'glibc-2.38/configure',
        'gramine-syscall.patch',
        'hp-timing.patch',
        # backporting the fix for `posix_memalign()` perf regression; drop when we update to glibc 2.39;
        # see the following:
        #  - https://sourceware.org/bugzilla/show_bug.cgi?id=30723
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=542b1105852568c3ebc712225ae78b8c8ba31a78
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=0dc7fc1cf094406a138e4d1bcf9553e59edcf89d
        'fix-bug-30723.patch',
        # backporting the fix for CVE-2023-4527; drop when we update to glibc 2.39;
        # see the following:
        #  - https://nvd.nist.gov/vuln/detail/CVE-2023-4527
        #  - https://sourceware.org/bugzilla/show_bug.cgi?id=30842
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=b25508dd774b617f99419bdc3cf2ace4560cd2d6
        'fix-CVE-2023-4527.patch',
        # backporting the fix for CVE-2023-4806; drop when we update to glibc 2.39;
        # see the following:
        #  - https://nvd.nist.gov/vuln/detail/CVE-2023-4806
        #  - https://sourceware.org/bugzilla/show_bug.cgi?id=30843
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=00ae4f10b504bc4564e9f22f00907093f1ab9338
        'fix-CVE-2023-4806.patch',
        # backporting the fix for CVE-2023-4911; drop when we update to glibc 2.39;
        # see the following:
        #  - https://nvd.nist.gov/vuln/detail/CVE-2023-4911
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=750a45a783906a19591fb8ff6b7841470f1f5701
        'fix-CVE-2023-4911.patch',
        # backporting the fix for CVE-2023-5156; drop when we update to glibc 2.39;
        # see the following:
        #  - https://nvd.nist.gov/vuln/detail/CVE-2023-5156
        #  - https://sourceware.org/bugzilla/show_bug.cgi?id=30884
        #  - https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=5ee59ca371b99984232d7584fe2b1a758b4421d3
        'fix-CVE-2023-5156.patch',
    ],

    output: glibc_output,

    console: true,

    install: true,
    install_dir: get_option('libdir') / 'gramine/runtime/glibc',
)
