export GO111MODULE=off

GO ?= go
GO_BUILD=$(GO) build
# Go module support: set `-mod=vendor` to use the vendored sources
ifeq ($(shell go help mod >/dev/null 2>&1 && echo true), true)
	GO_BUILD=GO111MODULE=on $(GO) build -mod=vendor
endif
DESTDIR ?=
SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)
PROJECT := github.com/containers/oci-seccomp-bpf-hook

HOOK_BIN_DIR ?= ${PREFIX}/libexec/oci/hooks.d/
ETCDIR ?= /etc
HOOK_DIR ?= ${ETCDIR}/containers/oci/hooks.d/

BUILDTAG_TRACE_HOOK ?= $(shell ./check_libbcc.sh)

ifeq (,$(BUILDTAG_TRACE_HOOK))
$(warning \
	Hook is being compiled without the oci_seccomp_bpf_hook build tag.\
	Install libbcc to use the oci-seccomp-bpf-hook)
endif

all:
	if [ ! -z "$(BUILDTAG_TRACE_HOOK)" ] ; then \
		$(GO_BUILD) -tags $(BUILDTAG_TRACE_HOOK) -o bin/oci-seccomp-bpf-hook $(PROJECT)/src; \
	fi

vendor:
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

install:
	if [ ! -z "$(BUILDTAG_TRACE_HOOK)" ]; then \
		install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_BIN_DIR); \
		install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_DIR) ; \
		install ${SELINUXOPT} -m 755 bin/oci-seccomp-bpf-hook ${DESTDIR}$(HOOK_BIN_DIR) ; \
		install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-run.json ${DESTDIR}$(HOOK_DIR) ; \
		install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-stop.json ${DESTDIR}$(HOOK_DIR) ; \
	fi

