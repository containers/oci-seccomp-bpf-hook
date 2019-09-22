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

# Can be used for local testing (e.g., to set filters)
BATS_OPTS ?=

# If GOPATH not specified, use one in the local directory
ifeq ($(GOPATH),)
export GOPATH := $(CURDIR)/_output
unexport GOBIN
endif
FIRST_GOPATH := $(firstword $(subst :, ,$(GOPATH)))
GOPKGDIR := $(FIRST_GOPATH)/src/$(PROJECT)
GOPKGBASEDIR ?= $(shell dirname "$(GOPKGDIR)")

GOBIN := $(shell $(GO) env GOBIN)
ifeq ($(GOBIN),)
GOBIN := $(FIRST_GOPATH)/bin
endif


.PHONY: all
all: docs binary

.PHONY: docs
docs:
	$(MAKE) -C docs

.PHONY: all
binary:
	$(GO_BUILD) -o bin/oci-seccomp-bpf-hook $(PROJECT)

.PHONY: validate
validate: .install.golangci-lint
	golangci-lint run

.install.golangci-lint:
	if [ ! -x "$(GOBIN)/golangci-lint" ]; then \
		curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(GOBIN)/ v1.18.0; \
	fi

.PHONY: vendor
vendor:
	export GO111MODULE=on \
		$(GO) mod tidy && \
		$(GO) mod vendor && \
		$(GO) mod verify

.PHONY: test-integration
test-integration:
	@echo
	@echo "==> Running integration tests (must be run as root)"
	bats $(BATS_OPTS) test/

install: all
	install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_BIN_DIR)
	install ${SELINUXOPT} -d -m 755 ${DESTDIR}$(HOOK_DIR)
	install ${SELINUXOPT} -m 755 bin/oci-seccomp-bpf-hook ${DESTDIR}$(HOOK_BIN_DIR)
	install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-run.json ${DESTDIR}$(HOOK_DIR)
	sed -i 's|HOOK_BIN_DIR|$(HOOK_BIN_DIR)|g' ${DESTDIR}$(HOOK_DIR)/oci-seccomp-bpf-hook-run.json
	install ${SELINUXOPT} -m 644 oci-seccomp-bpf-hook-stop.json ${DESTDIR}$(HOOK_DIR)
	sed -i 's|HOOK_BIN_DIR|$(HOOK_BIN_DIR)|g' ${DESTDIR}$(HOOK_DIR)/oci-seccomp-bpf-hook-stop.json
	$(MAKE) -C docs install

clean: ## Clean artifacts
	$(MAKE) -C docs clean
	rm -rf \
		bin
	find . -name \*~ -delete
	find . -name \#\* -delete
