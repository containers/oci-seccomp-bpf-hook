package main

import _ "embed"

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
	// HasArg0 is true for syscalls whose first argument is being profiled.
	HasArg0 bool
	_       [2]byte // padding to align Arg0
	Arg0    uint32
}

//go:embed bpf/ebpf.c
var source string
