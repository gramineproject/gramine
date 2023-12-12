# Copyright (c) 2021-2022 Wojtek Porczyk <woju@invisiblethingslab.com>

Name: gramine
Version: 1.6
Release: 1%{?dist}
Group: Development Tools
Summary: A lightweight usermode guest OS designed to run a single Linux application
License: LGPLv3+
URL: https://gramineproject.io
BuildArch: x86_64

Source0: %{name}-%{version}.tar.gz

BuildRequires: bison
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: jq
BuildRequires: make
BuildRequires: meson >= 0.56
BuildRequires: ninja-build >= 1.8
BuildRequires: nasm
BuildRequires: patch
BuildRequires: perl
BuildRequires: protobuf-c-compiler
BuildRequires: protobuf-c-devel
BuildRequires: python3-devel
BuildRequires: python3-recommonmark
BuildRequires: python3-sphinx
BuildRequires: python3-sphinx_rtd_theme

Requires: python3-click >= 6.7
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
%setup -q

%build
unset PKG_CONFIG_PATH

%meson \
    --buildtype=release \
    -Ddirect=enabled \
    -Dsgx=enabled \
    -Dsgx_driver=upstream

# assert correct version
if ! test "$(meson introspect --projectinfo "%{_vpath_builddir}" | jq -r .version)" = %{version}
then
    echo mismatched version: make sure that version in gramine.spec matches meson.build >&2
    exit 1
fi

%meson_build

%__make -C Documentation man

%install
%meson_install

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

%{_libdir}/pkgconfig/mbedtls_%{name}.pc
%{_libdir}/pkgconfig/ra_tls_%{name}.pc
%{_libdir}/pkgconfig/secret_prov_%{name}.pc

%{_libdir}/libmbed{crypto,tls,x509}_%{name}.{so*,a}

%{_libdir}/libra_tls*.so*
%{_libdir}/libra_tls_verify.a
%{_libdir}/libsecret_prov*.so*
%{_libdir}/libsecret_prov_verify.a
%{_libdir}/libsgx_util.a

%dir %{python3_sitearch}/%{name}libos
%{python3_sitearch}/%{name}libos/*.py
%{python3_sitearch}/%{name}libos/__pycache__
%dir %{python3_sitearch}/%{name}libos.dist-info
%{python3_sitearch}/%{name}libos.dist-info/METADATA
%{python3_sitearch}/%{name}libos.dist-info/entry_points.txt
%{python3_sitearch}/_%{name}libos_offsets.py
%{python3_sitearch}/__pycache__

%{_includedir}/gramine/*.h
%{_includedir}/gramine/mbedtls/*.h
%{_includedir}/gramine/psa/*.h

%{_mandir}/man1/%{name}-*.1*
%{_mandir}/man1/is-sgx-available.1*

%doc %{_licensedir}/%{name}/LICENSE*.txt
