[![Build Status](https://api.cirrus-ci.com/github/containers/oci-seccomp-bpf-hook.svg)](https://cirrus-ci.com/github/containers/oci-seccomp-bpf-hook/main)

# oci-seccomp-bpf-hook

This project provides an OCI hook to generate seccomp profiles by tracing the syscalls made by the container. The generated profile would allow all the syscalls made and deny every other syscall.

The syscalls are traced by launching a binary by using the prestart OCI hook. The binary started spawns a child process which attaches function `enter_trace` to the `raw_syscalls:sys_enter` tracepoint using eBPF. The function looks at all the syscalls made on the system and writes the syscalls which have the same PID namespace as the container to the perf buffer. The perf buffer is read by the process in the userspace and generates a seccomp profile when the container exits.

There are a few limitations to this approach:

* Needs `CAP_SYS_ADMIN` to run
* Compiles C code on the fly
* Cannot use `podman run --rm` along with this ability

To build it, we need extra dependencies namely bcc-devel and kernel-headers for Fedora and bcc-tools and linux-headers-[..] for Ubuntu.

Interface:

```bash
sudo podman run --annotation io.containers.trace-syscall="if:[absolute path to the input file];of:[absolute path to the output file]" IMAGE COMMAND
```

The profile will be created at the output path provided to the annotation. Providing `of:` is mandatory, while `if:` is optional. An input file can be used to create a baseline and newly recorded syscalls will be added to the set and written to the output. If a syscall is blocked in the base profile, then it will remain blocked in the output file even if it is recorded while tracing.

Please refer to an article on [Enable Sysadmin](https://www.redhat.com/sysadmin/container-security-seccomp) for more details.

`Copyright {2018-2022} {containers/oci-seccomp-bpf-hook maintainers}`
