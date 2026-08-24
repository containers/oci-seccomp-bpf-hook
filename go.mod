module github.com/containers/oci-seccomp-bpf-hook

go 1.25.7

require (
	github.com/iovisor/gobpf v0.2.1-0.20221005153822-16120a1bf4d4
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/seccomp/libseccomp-golang v0.11.1
	github.com/sirupsen/logrus v1.10.1
	github.com/stretchr/testify v1.12.1
	go.podman.io/common v0.69.1
	go.podman.io/storage v1.64.0
)

require (
	github.com/docker/go-units v0.5.0 // indirect
	github.com/moby/sys/capability v0.4.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
