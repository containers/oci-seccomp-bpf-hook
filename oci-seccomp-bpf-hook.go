package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/docker/docker/api/types"
	"github.com/iovisor/gobpf/bcc" //nolint
	spec "github.com/opencontainers/runtime-spec/specs-go"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/sirupsen/logrus"
	lsyslog "github.com/sirupsen/logrus/hooks/syslog"
)

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
// by bcc. $PARENT_PID get's replaced before compilation with the PID of the container
// Complete documentation is available at
// https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
const source string = `
#include <linux/bpf.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

// BPF_HASH used to store the PID namespace of the parent PID
// of the processes inside the container.
BPF_HASH(parent_namespace, u64, unsigned int);

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
    struct task_struct* task;

    data.pid = bpf_get_current_pid_tgid();
    data.id = (int)args->id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    task = (struct task_struct*)bpf_get_current_task();
    struct nsproxy* ns = task->nsproxy;
    unsigned int inum = ns->pid_ns_for_children->ns.inum;

    if (data.pid == $PARENT_PID) {
        parent_namespace.update(&key, &inum);
    }
    unsigned int* parent_inum = parent_namespace.lookup_or_init(&key, &zero);

    if (*parent_inum != inum) {
        return 0;
    }

    data.stopTracing = false;
    events.perf_submit(args, &data, sizeof(data));
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

// version is the version string of the hook. Set at build time.
var version string

func main() {

	log := logrus.New()
	hook, err := lsyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
	if err == nil {
		log.Hooks.Add(hook)
	}

	runBPF := flag.Int("r", 0, "-r [PID] run the BPF function and attach to the pid")
	outputFile := flag.String("o", "", "path of the file to save the seccomp profile")
	inputFile := flag.String("i", "", "path of the input file")
	start := flag.Bool("s", false, "Start the hook which would execute a process to trace syscalls made by the container")
	printVersion := flag.Bool("version", false, "Print the hook's version")

	flag.Parse()

	if *printVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if *outputFile != "" {
		if !filepath.IsAbs(*outputFile) {
			log.Fatal("output filepath is not absolute")
		}
	}

	if *inputFile != "" {
		if !filepath.IsAbs(*inputFile) {
			log.Fatal("input filepath is not absolute")
		}
	}

	logfilePath, err := filepath.Abs("trace-log")
	if err != nil {
		log.Error(err)
	}
	logfile, err := os.OpenFile(logfilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Errorf("error opening file: %v", err)
	}

	defer logfile.Close()
	formatter := new(logrus.TextFormatter)
	formatter.FullTimestamp = true
	log.SetFormatter(formatter)
	log.SetOutput(logfile)

	if *runBPF > 0 {
		if err := runBPFSource(*runBPF, *outputFile, *inputFile, log); err != nil {
			log.Fatal(err)
		}
	} else if *start {
		if err := startFloatingProcess(); err != nil {
			log.Fatal(err)
		}
	}
}

// Start a process which runs the BPF source and detach the process
func startFloatingProcess() error {
	var s spec.State
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&s)
	if err != nil {
		return err
	}
	pid := s.Pid

	annotation := s.Annotations["io.containers.trace-syscall"]

	outputFile, inputFile, err := parseAnnotation(annotation)
	if err != nil {
		return err
	}

	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil,
			nil,
		},
	}
	if pid > 0 {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGUSR1)

		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot determine executable path:%q", err.Error())
		}

		process, err := os.StartProcess(executable, []string{executable, "-r", strconv.Itoa(pid), "-o", outputFile, "-i", inputFile}, attr)
		if err != nil {
			return fmt.Errorf("cannot launch process err: %q", err.Error())
		}

		<-sig

		processPID := process.Pid
		f, err := os.Create("pidfile")
		if err != nil {
			return fmt.Errorf("cannot write pid to file err:%q", err.Error())
		}
		defer f.Close()
		_, err = f.WriteString(strconv.Itoa(processPID))
		if err != nil {
			return fmt.Errorf("cannot write pid to the file")
		}
		err = process.Release()
		if err != nil {
			return fmt.Errorf("cannot detach process err:%q", err.Error())
		}

	} else {
		return fmt.Errorf("container not running")
	}
	return nil
}

// run the BPF source and attach it to raw_syscalls:sys_enter tracepoint
func runBPFSource(pid int, profilePath string, inputFile string, log *logrus.Logger) error {
	var wg sync.WaitGroup

	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)

	if err != nil {
		return fmt.Errorf("cannot find the parent process pid %d : %q", ppid, err)
	}

	log.Println("Running floating process PID to attach:", pid)
	syscalls := make(map[string]int, 303)
	src := strings.Replace(source, "$PARENT_PID", strconv.Itoa(pid), -1)
	m := bcc.NewModule(src, []string{})
	defer m.Close()

	enterTrace, err := m.LoadTracepoint("enter_trace")
	if err != nil {
		return err
	}

	checkExit, err := m.LoadTracepoint("check_exit")
	if err != nil {
		return err
	}

	log.Println("Loaded tracepoints")

	if err := m.AttachTracepoint("raw_syscalls:sys_enter", enterTrace); err != nil {
		return fmt.Errorf("unable to load enter_trace err:%q", err.Error())
	}
	if err := m.AttachTracepoint("sched:sched_process_exit", checkExit); err != nil {
		return fmt.Errorf("unable to load check_exit err:%q", err.Error())
	}

	// send a signal to the parent process to indicate the compilation has been completed
	err = parentProcess.Signal(syscall.SIGUSR1)
	if err != nil {
		return err
	}

	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel)
	if err != nil {
		return fmt.Errorf("unable to init perf map err:%q", err.Error())
	}

	reachedPRCTL := false // Reached PRCTL syscall

	// Initialises a wait group for the goroutine which reads the perf buffer
	wg.Add(1)

	go func() {
		var e event
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
			if err != nil {
				log.Errorf("failed to decode received data '%s': %s\n", data, err)
				continue
			}
			if e.StopTracing {
				break
			} else {
				name, err := getName(e.ID)
				if err != nil {
					log.Errorf("failed to get name of syscall from id : %d received : %q", e.ID, name)
				}
				// syscalls are not recorded until prctl() is called
				if name == "prctl" {
					reachedPRCTL = true
				}
				if reachedPRCTL {
					syscalls[name]++
				}
			}
		}
		wg.Done()
	}()
	perfMap.Start()
	log.Println("PerfMap Start")

	// Waiting for the goroutine which is reading the perf buffer to be done
	// The goroutine will exit when the container exits
	wg.Wait()

	perfMap.Stop()
	log.Println("PerfMap Stop")
	if err := generateProfile(syscalls, profilePath, inputFile); err != nil {
		return err
	}
	return nil
}

// generate the seccomp profile from the syscalls provided
func generateProfile(calls map[string]int, fileName string, inputFile string) error {
	outputProfile := types.Seccomp{}
	inputProfile := types.Seccomp{}

	if inputFile != "" {
		input, err := ioutil.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("cannot read input file err: %q", err)
		}
		err = json.Unmarshal(input, &inputProfile)
		if err != nil {
			return fmt.Errorf("cannot unmarshal input file err: %q", err)
		}
	}

	var names []string
	for syscallName, syscallID := range calls {
		if syscallID > 0 {
			if !profileContainsSyscall(&inputProfile, syscallName) {
				names = append(names, syscallName)
			}
		}
	}
	sort.Strings(names)

	outputProfile = inputProfile
	outputProfile.DefaultAction = types.ActErrno

	outputProfile.Syscalls = append(outputProfile.Syscalls, &types.Syscall{
		Action: types.ActAllow,
		Names:  names,
		Args:   []*types.Arg{},
	})

	sJSON, err := json.Marshal(outputProfile)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(fileName, sJSON, 0644); err != nil {
		return err
	}
	return nil
}

func parseAnnotation(annotation string) (outputFile string, inputFile string, err error) {
	annotationSplit := strings.Split(annotation, ";")
	if len(annotationSplit) > 2 {
		return "", "", fmt.Errorf("The annotation must have only one \";\"")
	}
	for _, path := range annotationSplit {
		if strings.HasPrefix(path, "if:") {
			inputFile = strings.TrimSpace(strings.TrimPrefix(path, "if:"))
			if !filepath.IsAbs(inputFile) {
				return "", "", fmt.Errorf("The path to the input file is not absolute: %q", inputFile)
			}

			// Check if input file exists and is not malformed

			inputProfile := types.Seccomp{}
			input, err := ioutil.ReadFile(inputFile)
			if err != nil {
				return "", "", fmt.Errorf("cannot read input file %q err: %q", inputFile, err)
			}
			err = json.Unmarshal(input, &inputProfile)
			if err != nil {
				return "", "", fmt.Errorf("cannot unmarshal input file %q err: %q", inputFile, err)
			}

			continue
		}
		if strings.HasPrefix(path, "of:") {
			outputFile = strings.TrimSpace(strings.TrimPrefix(path, "of:"))
			if !filepath.IsAbs(outputFile) {
				return "", "", fmt.Errorf("The path to the output file is not absolute: %q", outputFile)
			}
			continue
		}
		return "", "", fmt.Errorf("%q not an input or an output annotation", path)
	}
	if outputFile == "" {
		return "", "", fmt.Errorf("providing output file is mandatory")
	}
	return outputFile, inputFile, nil
}

// get the name of the syscall from it's ID
func getName(id uint32) (string, error) {
	name, err := seccomp.ScmpSyscall(id).GetName()
	return name, err
}

// checks if the input profile contains the syscalls recorded while tracing the process
func profileContainsSyscall(input *types.Seccomp, syscall string) bool {
	for _, s := range input.Syscalls {
		if s.Name == syscall {
			return true
		}
		for _, name := range s.Names {
			if name == syscall {
				return true
			}
		}
	}
	return false
}
