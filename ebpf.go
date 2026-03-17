package main

// event struct used to read data from the perf ring buffer
type event struct {
	// PID of the process making the syscall
	Pid uint32
	// syscall number
	ID uint32
	// Command which makes the syscall
	Command [16]byte
	// Stops tracing syscalls if true
	StopTracing bool
}

// the source is a bpf program compiled at runtime. Some macro's like
// BPF_HASH and BPF_PERF_OUTPUT are expanded during compilation
// by bcc. $PARENT_PID gets replaced before compilation with the PID of the container
// Complete documentation is available at
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
const source string = `
#include <uapi/linux/ptrace.h>
#include <asm/unistd.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>

// Store the mount namespace pointer of the container's init process.
// All processes in the same mount namespace share this pointer,
// including those in sub-cgroups.
BPF_HASH(parent_namespace, u64, u64);

BPF_HASH(seen_syscalls, int, u64);

// Opens a custom BPF table to push data to user space via perf ring buffer
BPF_PERF_OUTPUT(events);

// data_t used to store the data received from the event
struct syscall_data {
    // PID of the process
    u32 pid;
    // the syscall number
    u32 id;
    // command which is making the syscall
    char comm[16];
    // Stops tracing syscalls if true
    bool stopTracing;
};

// enter_trace is attached to raw_syscalls:sys_enter.  It records
// syscalls made by processes in the same mount namespace as $PARENT_PID.
// We compare the nsproxy->mnt_ns pointer directly instead of reading
// ns_common.inum, because ns_common's layout changes across kernel
// versions and including its header breaks BCC compilation on newer
// kernels.
int enter_trace(struct tracepoint__raw_syscalls__sys_enter* args)
{
    struct syscall_data data = {};
    u64 key = 0;
    int id = (int)args->id;

    u64 pidtgid = bpf_get_current_pid_tgid();
    data.pid = (u32)pidtgid;
    data.id = id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 mnt_ns_ptr = (u64)task->nsproxy->mnt_ns;

    if (data.pid == $PARENT_PID) {
        parent_namespace.update(&key, &mnt_ns_ptr);
    }
    u64 *parent_ns = parent_namespace.lookup(&key);

    if (parent_ns == NULL || *parent_ns != mnt_ns_ptr) {
        return 0;
    }

    // Syscalls are not recorded until prctl() is called. The first
    // invocation of prctl is guaranteed to happen by the supported
    // OCI runtimes (i.e., runc and crun) as it's being called when
    // setting the seccomp profile.
    int prctl_nr = __NR_prctl;
    u64 *prctl_seen = seen_syscalls.lookup(&prctl_nr);

    u64 seen = 0;
    u64 *tmp = seen_syscalls.lookup(&id);
    if (tmp != NULL)
       seen = *tmp;

    if (id == __NR_prctl) {
        if (seen > 1)
            return 0;

        // First prctl: record it without generating an event.
        if (seen == 0) {
            seen = 1;
            seen_syscalls.update(&id, &seen);
            return 0;
        }
    } else {
        if (seen > 0)
            return 0;

        if (prctl_seen == NULL)
            return 0;
    }

    data.stopTracing = false;
    events.perf_submit(args, &data, sizeof(data));

    seen++;
    seen_syscalls.update(&id, &seen);
    return 0;
}

// check_exit detects when the container's init process exits.
int check_exit(struct tracepoint__sched__sched_process_exit* args)
{
    if (args->pid == $PARENT_PID) {
        struct syscall_data data = {};
        data.pid = args->pid;
        data.id = 0;
        data.stopTracing = true;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}
`
