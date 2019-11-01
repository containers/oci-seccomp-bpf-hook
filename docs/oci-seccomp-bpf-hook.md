oci-seccomp-bpf-hook(1) -- OCI systemd hook
=============================================

## SYNOPSIS

`oci-seccomp-bpf-hook` prestart [container.json]

## DESCRIPTION

The oci hook `oci-seccomp-bpf-hook` generates seccomp profiles by tracing the syscalls made by the container. The generated profile would whitelist all the syscalls made and blacklist all other syscall.

The syscalls are traced by launching a binary using the OCI prestart hook. The binary spawns a child process which attaches the function `enter_trace` to the `raw_syscalls:sys_enter` tracepoint using eBPF. The hook buffers all syscalls made by processes within the PID namespace of the container.  When the container exits, the hook writes out the seccomp profile using all of the syscalls stored in the buffer.

There are a few limitations to this approach:

Requires:

    Root privileges (CAP_SYS_ADMIN).  Hook will not work with rootless containers.

    The bcc tool chain and kernel-headers to run. BPF programs must be compiled before running to match the current kernel.

    A container engine that supports OCI Hooks.


Annotation:

    The oci-seccomp-bpf-hook requires the container be run with the annotation `io.containers.trace-syscall=`. It must include an output file parameter `of:[output file]` This output file must be a absolute path.

    Optionally you can include an input file parameter `if:[input file]` pointing to a previously generated seccomp profile file.  This input file must also be an absolute path.  If specified the oci-seccomp-bpf-hook will read in the input seccomp profile and preload the list of syscalls.

    The profile will be created at the output path provided to the annotation. An input file can be used to create a baseline and newly recorded syscalls will be added to the set and written to the output. If a syscall is blocked in the base profile, then it will remain blocked in the output file even if it is recorded while tracing.

    This annotation can be used directly via container engines like Podman or passed into the container engine by Kubernetes.

## EXAMPLES
   `sudo podman run --annotation io.containers.trace-syscall="of:/tmp/seccomp-new.json" IMAGE COMMAND`
   
   `sudo podman run --annotation io.containers.trace-syscall="if:/tmp/seccomp-origin.json;of:/tmp/seccomp-new.json" IMAGE COMMAND`

## FILES

OCI hook configuration file for prestart

`/usr/share/containers/oci/hooks.d/oci-seccomp-bpf-hook.json`

`/etc/containers/oci/hooks.d/oci-seccomp-bpf-hook.json (Override)`


## SEE ALSO
podman(1), seccomp(2), oci-hooks(5)

## AUTHORS
Divyansh Kamboj <kambojdivyansh2000@gmail.com>

Valentin Rothberg <vrothberg@redhat.com>

Dan Walsh <dwalsh@redhat.com>
