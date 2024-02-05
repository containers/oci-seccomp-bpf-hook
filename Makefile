export GO111MODULE=off

GO ?= go
GO_BUILD=$(GO) build
# Go module support: set `-mod=vendor` to use the vendored sources
ifeq ($(shell go help mod >/dev/null 2>&1 && echo true), true)
	GO_BUILD=GO111MODULE=on $(GO) build -mod=vendor
endif
DESTDIR ?=
PREFIX ?= /usr/local
SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)
PROJECT := github.com/containers/oci-seccomp-bpf-hook
HOOK_BIN_DIR ?= $(PREFIX)/libexec/oci/hooks.d
ETCDIR ?= /etc
HOOK_DIR ?= $(PREFIX)/share/containers/oci/hooks.d/
OSBH_VERSION ?= $(shell cat ./VERSION)

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

define go-get
	env GO111MODULE=off \
		$(GO) get -u $(1)
endef

.PHONY: all
all: docs binary

.PHONY: docs
docs:
	$(MAKE) -C docs PREFIX=$(PREFIX)

.PHONY: binary
binary:
	$(GO_BUILD) -mod=vendor -o bin/oci-seccomp-bpf-hook -ldflags "-X main.version=$(OSBH_VERSION)" $(PROJECT)

.PHONY: validate
validate:
	./build/golangci-lint run

.PHONY: vendor
vendor:
	GO111MODULE=on $(GO) mod tidy
	GO111MODULE=on $(GO) mod vendor
	GO111MODULE=on $(GO) mod verify

.PHONY: test-integration
test-integration:
	@echo
	@echo "==> Running integration tests (must be run as root)"
	./hack/check_root.sh
	bats $(BATS_OPTS) test/

.PHONY: test-unit
test-unit:
	$(GO) test -v $(PROJECT)


.PHONY: install.tools
install.tools: .install.golangci-lint .install.md2man

.install.golangci-lint: VERSION=v1.55.2
.install.golangci-lint:
	curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/$(VERSION)/install.sh | sh -s -- -b ./build $(VERSION)

.install.md2man:
	if [ -z "$(shell type -P go-md2man)" ]; then \
		   $(call go-get,github.com/cpuguy83/go-md2man); \
	fi

.PHONY: install.docs-nobuild
install.docs-nobuild:
	$(MAKE) -C docs install-nobuild

.PHONY: install.docs
install.docs:
	$(MAKE) -C docs install

.PHONY: install-nobuild
install-nobuild: install.docs-nobuild
	install $(SELINUXOPT) -d -m 755 $(DESTDIR)$(HOOK_BIN_DIR)
	install $(SELINUXOPT) -d -m 755 $(DESTDIR)$(HOOK_DIR)
	install $(SELINUXOPT) -m 755 bin/oci-seccomp-bpf-hook $(DESTDIR)$(HOOK_BIN_DIR)
	install $(SELINUXOPT) -m 644 oci-seccomp-bpf-hook.json $(DESTDIR)$(HOOK_DIR)
	sed -i 's|HOOK_BIN_DIR|$(HOOK_BIN_DIR)|g' $(DESTDIR)$(HOOK_DIR)/oci-seccomp-bpf-hook.json

.PHONY: install
install: docs install-nobuild

clean: ## Clean artifacts
	$(MAKE) -C docs clean
	rm -rf \
		bin
	find . -name \*~ -delete
	find . -name \#\* -delete
