module github.com/containers/oci-seccomp-bpf-hook

go 1.12

require (
	github.com/docker/docker v1.13.1
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/iovisor/gobpf v0.0.0-20190827113749-5e47cda1484e
	github.com/opencontainers/runtime-spec v1.0.1
	github.com/seccomp/libseccomp-golang v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.2.2
)
