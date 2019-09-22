export GO111MODULE=off

GO ?= go
GO_BUILD=$(GO) build
# Go module support: set `-mod=vendor` to use the vendored sources
ifeq ($(shell go help mod >/dev/null 2>&1 && echo true), true)
	GO_BUILD=GO111MODULE=on $(GO) build -mod=vendor
endif
DESTDIR ?=
PREFIX ?= /usr
SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)
PROJECT := github.com/containers/oci-seccomp-bpf-hook
HOOK_BIN_DIR ?= ${PREFIX}/libexec/oci/hooks.d
ETCDIR ?= /etc
HOOK_DIR ?= ${PREFIX}/share/containers/oci/hooks.d/

all:
	$(GO_BUILD) -o bin/oci-seccomp-bpf-hook $(PROJECT)

vendor:
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

install:
	install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_BIN_DIR)
	install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_DIR)
	install ${SELINUXOPT} -m 755 bin/oci-seccomp-bpf-hook ${DESTDIR}$(HOOK_BIN_DIR)
	install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-run.json ${DESTDIR}$(HOOK_DIR)
	sed -i 's|HOOK_BIN_DIR|$(HOOK_BIN_DIR)|g' ${DESTDIR}$(HOOK_DIR)/oci-seccomp-bpf-hook-run.json
	install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-stop.json ${DESTDIR}$(HOOK_DIR)
	sed -i 's|HOOK_BIN_DIR|$(HOOK_BIN_DIR)|g' ${DESTDIR}$(HOOK_DIR)/oci-seccomp-bpf-hook-stop.json

