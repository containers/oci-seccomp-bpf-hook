%global with_devel 0
%global with_bundled 1
%global with_debug 1
%global with_check 0
%global with_unit_test 0

%if 0%{?with_debug}
%global _find_debuginfo_dwz_opts %{nil}
%global _dwz_low_mem_die_limit 0
%else
%global debug_package   %{nil}
%endif

# %if ! 0% {?gobuild:1}
%define gobuild(o:) go build -tags="$BUILDTAGS" -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n')" -a -v -x %{?**};
#% endif

%global provider github
%global provider_tld com
%global project containers
%global repo oci-seccomp-bpf-hook
# https://github.com/containers/oci-seccomp-bpf-hook
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path %{provider_prefix}
%global git0 https://%{provider}.%{provider_tld}/%{project}/%{repo}
%global commit0 a9b7d0b7efd2101c7406d184253b5ba3d7188e83
%global shortcommit0 %(c=%{commit0}; echo ${c:0:8})

Name: oci-seccomp-bpf-hook
Version: 0.0.1
Release: 0.1.git%{shortcommit0}%{?dist}
Summary: OCI Hook to generate seccomp json files based on EBF syscalls used by container
License: GPLv2
URL: %{git0}
Source0: %{git0}/archive/%{commit0}/%{repo}-%{shortcommit0}.tar.gz
BuildRequires: glib2-devel
BuildRequires: glibc-devel
BuildRequires: bcc-devel
BuildRequires: git
BuildRequires: gpgme-devel
BuildRequires: libseccomp-devel
BuildRequires: make

%description
%{summary}
%{repo} provides a library for applications looking to use
the Container Pod concept popularized by Kubernetes.

%package remote
Summary:       Remote Oci-Seccomp-Bpf client

%description remote
%{summary}
%{repo} provides a library for applications looking to use
the Container Pod concept popularized by Kubernetes.


%prep
%autosetup -Sgit -n %{repo}-%{commit0}

%build
mkdir _build
pushd _build
mkdir -p src/%{provider}.%{provider_tld}/%{project}
ln -s ../../../../ src/%{import_path}
popd
ln -s vendor src

export GOPATH=$(pwd)/_build:$(pwd):$(pwd):%{gopath}
export BUILDTAGS=""
BUILDTAGS=$BUILDTAGS make

%install
%{__make} DESTDIR=%{buildroot} PREFIX=%{_prefix} ETCDIR=%{buildroot}%{_sysconfdir} install

%check
%if 0%{?with_check} && 0%{?with_unit_test} && 0%{?with_devel}
# Since we aren't packaging up the vendor directory we need to link
# back to it somehow. Hack it up so that we can add the vendor
# directory from BUILD dir as a gopath to be searched when executing
# tests from the BUILDROOT dir.
ln -s ./ ./vendor/src # ./vendor/src -> ./vendor

export GOPATH=%{buildroot}/%{gopath}:$(pwd)/vendor:%{gopath}

%if ! 0%{?gotest:1}
%global gotest go test
%endif

%gotest %{import_path}/src/%{name}
%endif

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files
%license LICENSE
%doc README.md
%dir %{_libexecdir}/oci/hooks.d
%{_libexecdir}/oci/hooks.d/%{name}
%{_datadir}/containers/oci/hooks.d/%{name}.json
%{_mandir}/man1/%{name}.1*

%changelog
* Wed Aug 12 2020 Sascha Grunert <sgrunert@suse.com>
- remove unused version env var on build

* Mon Sep 23 2019 Jindrich Novy <jnovy@redhat.com> - 0.0.1-0.1.gite200a9ed
- fix spec file and build

* Sun Sep 22 2019 Dan Walsh <dwalsh@redhat.com> - 0.0.1
- Initial Version
