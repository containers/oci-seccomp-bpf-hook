oci-seccomp-bpf-hook(1) -- OCI systemd hook
=============================================

## SYNOPSIS

`oci-seccomp-bpf-hook` prestart [container.json]

`oci-seccomp-bpf-hook` poststop

## DESCRIPTION

The oci hook oci-seccomp-bpf-hook is used to generate seccomp profiles by tracing the syscalls made by the container. The generated profile would whitelist all the syscalls made and blacklist every other syscall.

The syscalls are traced by launching a binary by using the prestart OCI hook. The binary started spawns a child process which attaches function `enter_trace` to the `raw_syscalls:sys_enter` tracepoint using eBPF. The function looks at all the syscalls made on the system and writes the syscalls which have the same PID namespace as the container to the perf buffer. The perf buffer is read by the process in the userspace and generates a seccomp profile when the container exits.

There are a few limitations to this approach:

* Needs CAP_SYS_ADMIN to run
* Compiles C code on the fly
* Cannot use podman run --rm along with this ability

To build it, we need dependencies namely bcc-devel and kernel-headers for Fedora and bcc-tools and linux-headers-[..] for Ubuntu.

Interface:

```
sudo podman run --annotation io.containers.trace-syscall="if:[absolute path to the input file];of:[absolute path to the output file]" IMAGE COMMAND
```

The profile will be created at the output path provided to the annotation. An input file can be used to create a baseline and newly recorded syscalls will be added to the set and written to the output. If a syscall is blocked in the base profile, then it will remain blocked in the output file even if it is recorded while tracing.

## FILES

OCI hook configuration file for prestart

* /usr/share/containers/oci/hooks.d/oci-seccomp-bpf-hook-run.json
* /etc/containers/oci/hooks.d/oci-seccomp-bpf-hook-run.json (Override)


## SEE ALSO
podman(1), seccomp(2), oci-hooks(5)

## AUTHORS
Divyansh Kamboj <kambojdivyansh2000@gmail.com>
Valentin Rothberg <vrothberg@redhat.com>
Dan Walsh <dwalsh@redhat.com>
