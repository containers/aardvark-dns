%global debug_package %{nil}

Name: aardvark-dns
Epoch: 100
Version: 0
%define build_datestamp %{lua: print(os.date("%Y%m%d"))}
%define build_timestamp %{lua: print(os.date("%H%M%S"))}
Release: %{build_datestamp}.%{build_timestamp}
Summary: Authoritative DNS server for A/AAAA container records
License: ASL 2.0
URL: https://github.com/containers/%{name}
Source: %{url}/archive/main.tar.gz
BuildRequires: make
BuildRequires: cargo

ExclusiveArch:  %{rust_arches}
%if %{__cargo_skip_build}
BuildArch:      noarch
%endif

%global _description %{expand:
%{summary}}

%description %{_description}

%prep
%autosetup -n %{name}-main
sed -i 's/install: docs build/install:/' Makefile

%build
%{__make} build

%install
%{__make} DESTDIR=%{buildroot} PREFIX=%{_prefix} install


%files
%license LICENSE
%dir %{_libexecdir}/podman
%{_libexecdir}/podman/%{name}

%changelog
* Fri Dec 03 2021 Lokesh Mandvekar <lsm5@fedoraproject.org> - %{version}-%{release}
- auto copr build
