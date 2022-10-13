# Copyright (c) 2021-2022 Wojtek Porczyk <woju@invisiblethingslab.com>

%global vnt %{lua: ver = rpm.expand('%{version}'):gsub('~', '-') print(ver)}

Name: gramine
Version: 1.3.1post~UNRELEASED
Release: 1%{?dist}
Group: Development Tools
Summary: A lightweight usermode guest OS designed to run a single Linux application
License: LGPLv3+
URL: https://gramineproject.io
BuildArch: x86_64

Source0: %{name}-%{vnt}.tar.gz

BuildRequires: bison
BuildRequires: cjson-devel
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: meson >= 0.56
BuildRequires: ninja-build >= 1.8
BuildRequires: nasm
BuildRequires: patch
BuildRequires: protobuf-c-compiler
BuildRequires: protobuf-c-devel
BuildRequires: python3-devel
BuildRequires: python3-sphinx
BuildRequires: python3-sphinx_rtd_theme

Requires: cjson
Requires: python3-click
Requires: python3-cryptography
Requires: python3-jinja2
Requires: python3-protobuf
Requires: python3-pyelftools
Requires: python3-tomli >= 1.1.0
Requires: python3-tomli-w >= 0.4.0

%global debug_package %{nil}
%global __meson_auto_features disabled

# clear the environment; see https://src.fedoraproject.org/rpms/redhat-rpm-config/blob/rawhide/f/macros
%define build_cflags %{nil}
%define build_cxxflags %{nil}
%define build_fflags %{nil}
%define build_ldflags %{nil}

%description
A lightweight usermode guest OS designed to run a single Linux application

%prep
%setup -q -n %{name}-%{vnt}

%build
unset PKG_CONFIG_PATH

%meson \
    --buildtype=release \
    -Ddirect=enabled \
    -Dsgx=enabled \
    -Dsgx_driver=upstream
%meson_build

%__make -C Documentation man

%install
%meson_install

#rm -f %{buildroot}/%{_libdir}/%{name}/direct/libpal.a

#ln -sf ld-linux-x86-64.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/ld.so
#ln -sf libanl.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libanl.so
#ln -sf libc.so.6 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libc.so
#ln -sf libdl.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libdl.so
#ln -sf libm.so.6 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libm.so
#ln -sf libmvec.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libmvec.so
#ln -sf libnsl.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libnsl.so
#ln -sf libnss_compat.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libnss_compat.so
#ln -sf libnss_db.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libnss_db.so
#ln -sf libnss_dns.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libnss_dns.so
#ln -sf libnss_files.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libnss_files.so
#ln -sf libpthread.so.0 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libpthread.so
#ln -sf libresolv.so.2 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libresolv.so
#ln -sf librt.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/librt.so
#ln -sf libthread_db.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libthread_db.so
#ln -sf libutil.so.1 %{buildroot}/%{_libdir}/%{name}/runtime/glibc/libutil.so
#ln -sf libmbedcrypto_%{name}.so.6 %{buildroot}/%{_libdir}/libmbedcrypto_%{name}.so
#ln -sf libmbedtls_%{name}.so.13 %{buildroot}/%{_libdir}/libmbedtls_%{name}.so
#ln -sf libmbedx509_%{name}.so.1 %{buildroot}/%{_libdir}/libmbedx509_%{name}.so

install -d %{buildroot}/%{_mandir}/man1
install -t %{buildroot}/%{_mandir}/man1 Documentation/_build/man/*.1

install -d %{buildroot}/%{_licensedir}/%{name}
install -t %{buildroot}/%{_licensedir}/%{name} LICENSE*.txt

%files
%{_bindir}/%{name}-*
%{_bindir}/is-sgx-available

%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/direct
%{_libdir}/%{name}/direct/libpal.so
%{_libdir}/%{name}/direct/loader
%dir %{_libdir}/%{name}/sgx
%{_libdir}/%{name}/sgx/libpal.so
%{_libdir}/%{name}/sgx/loader

%{_libdir}/%{name}/libsysdb.so

%dir %{_libdir}/%{name}/runtime
%{_libdir}/%{name}/runtime/glibc
%{_libdir}/%{name}/runtime/musl

%{_libdir}/pkgconfig/mbedtls_%{name}.pc
%{_libdir}/libmbed{crypto,tls,x509}_%{name}.{so*,a}

%{_libdir}/libra_tls*.so*
%{_libdir}/libsecret_prov*.so*
%{_libdir}/libsgx_util.a

%dir %{python3_sitearch}/%{name}libos
%{python3_sitearch}/%{name}libos/*.py
%{python3_sitearch}/%{name}libos/__pycache__

%{_includedir}/gramine/mbedtls/*.h
%{_includedir}/gramine/psa/*.h

%{_mandir}/man1/%{name}-*.1*
%{_mandir}/man1/is-sgx-available.1*

%doc %{_licensedir}/%{name}/LICENSE*.txt
