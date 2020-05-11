module github.com/containers/oci-seccomp-bpf-hook

go 1.12

require (
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/iovisor/gobpf v0.0.0-20200504095308-90dbbdfb1358
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.4.0
	golang.org/x/sys v0.0.0-20200509044756-6aff5f38e54f // indirect
)
