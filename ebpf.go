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
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

/*
 * mnt_namespace is defined in fs/mount.h and not part of the kernel headers.
 * Hence, we need a forward decl here to make the compiler eat the code.
 */
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

// BPF_HASH used to store the PID namespace of the parent PID
// of the processes inside the container.
BPF_HASH(parent_namespace, u64, unsigned int);

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

// enter_trace : function is attached to the kernel tracepoint raw_syscalls:sys_enter it is
// called whenever a syscall is made. The function stores the pid_namespace (task->nsproxy->pid_ns_for_children->ns.inum) of the PID which
// starts the container in the BPF_HASH called parent_namespace.
// The data of the syscall made by the process with the same pid_namespace as the parent_namespace is pushed to
// userspace using perf ring buffer

// specification of args from sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format
int enter_trace(struct tracepoint__raw_syscalls__sys_enter* args)
{
    struct syscall_data data = {};
    u64 key = 0;
    unsigned int zero = 0;
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    int id = (int)args->id;

    data.pid = bpf_get_current_pid_tgid();
    data.id = id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    task = (struct task_struct *)bpf_get_current_task();
    nsproxy = task->nsproxy;
    mnt_ns = nsproxy->mnt_ns;

    unsigned int inum = mnt_ns->ns.inum;

    if (data.pid == $PARENT_PID) {
        parent_namespace.update(&key, &inum);
    }
    unsigned int* parent_inum = parent_namespace.lookup_or_init(&key, &zero);

    if (parent_inum != NULL && *parent_inum != inum) {
        return 0;
    }

    u64 seen = 0, *tmp = seen_syscalls.lookup(&id);
    if (tmp != NULL)
       seen = *tmp;
    // Syscalls are not recorded until prctl() is called. The first
    // invocation of prctl is guaranteed to happen by the supported
    // OCI runtimes (i.e., runc and crun) as it's being called when
    // setting the seccomp profile.
    if (id == __NR_prctl) {
        // The syscall was already notified.
        if (seen > 1)
            return 0;

        // The first time we see prctl, we record it without generating
        // any event.
        if (seen == 0) {
            goto record_and_exit;
        }
    } else {
        // The syscall was already notified.
        if (seen > 0)
            return 0;
    }

    data.stopTracing = false;
    events.perf_submit(args, &data, sizeof(data));

record_and_exit:
    seen++;
    seen_syscalls.update(&id, &seen);
    return 0;
}

// Checks if the container has exited
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
