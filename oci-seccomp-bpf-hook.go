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
	"time"

	"github.com/docker/docker/api/types"
	"github.com/iovisor/gobpf/bcc"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

const (
	// ebpfTimout is the timeout in seconds to wait for the child process to signal
	// that the eBPF program finished compiling and attached to the tracee.
	ebpfTimeout = 10
	// inputPrefix is the prefix for input files in the runtime annotation.
	inputPrefix = "if:"
	// outputPrefix is the prefix for output files in the runtime annotation.
	outputPrefix = "of:"
)

var (
	// version is the version string of the hook. Set at build time.
	version string
	// errInvalidAnnotation denotes an error for an invalid runtime annotation.
	errInvalidAnnotation = errors.New("invalid annotation")
)

func main() {
	hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
	if err == nil {
		logrus.AddHook(hook)
	}
	logrus.Infof("Started OCI seccomp hook version %s", version)

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
			logrus.Fatal("output filepath is not absolute")
		}
	}

	if *inputFile != "" {
		if !filepath.IsAbs(*inputFile) {
			logrus.Fatal("input filepath is not absolute")
		}
	}

	if *runBPF > 0 {
		if err := runBPFSource(*runBPF, *outputFile, *inputFile); err != nil {
			logrus.Fatal(err)
		}
	} else if *start {
		if err := detachAndTrace(); err != nil {
			logrus.Fatal(err)
		}
	}
}

// detachAndTrace re-executes the current executable to "fork" in go-ish way and
// traces the provided PID.
func detachAndTrace() error {
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
			return errors.Wrap(err, "cannot determine executable")
		}

		process, err := os.StartProcess(executable, []string{"oci-seccomp-bpf-hook", "-r", strconv.Itoa(pid), "-o", outputFile, "-i", inputFile}, attr)
		if err != nil {
			return errors.Wrap(err, "cannot re-execute")
		}

		select {
		case <-sig:
			// Nothing to do, we can safely detach now.
			break
		case <-time.After(ebpfTimeout * time.Second):
			// For whatever reason, the child process did not send the signal
			// within the timeout.  So kill it and return an error to runc.
			if err := process.Kill(); err != nil {
				logrus.Errorf("error killing child process: %v", err)
			}
			return errors.Errorf("eBPF program didn't compile and attach within %d seconds", ebpfTimeout)
		}

		processPID := process.Pid
		f, err := os.Create("pidfile")
		if err != nil {
			return errors.Wrap(err, "cannot write pid to file err")
		}
		defer f.Close()
		_, err = f.WriteString(strconv.Itoa(processPID))
		if err != nil {
			return errors.Errorf("cannot write pid to the file")
		}
		err = process.Release()
		if err != nil {
			return errors.Wrap(err, "cannot detach process err")
		}

	} else {
		return errors.Errorf("container not running")
	}
	return nil
}

// run the BPF source and attach it to raw_syscalls:sys_enter tracepoint
func runBPFSource(pid int, profilePath string, inputFile string) error {
	var wg sync.WaitGroup

	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)

	if err != nil {
		return errors.Wrapf(err, "cannot find parent process %d", ppid)
	}

	logrus.Infof("Running floating process PID to attach: %d", pid)
	syscalls := make(map[string]int, 303)
	src := strings.Replace(source, "$PARENT_PID", strconv.Itoa(pid), -1)
	m := bcc.NewModule(src, []string{})
	defer m.Close()

	enterTrace, err := m.LoadTracepoint("enter_trace")
	if err != nil {
		return errors.Wrap(err, "error loading tracepoint")
	}
	checkExit, err := m.LoadTracepoint("check_exit")
	if err != nil {
		return errors.Wrap(err, "error loading tracepoint")
	}
	logrus.Info("Loaded tracepoints")

	if err := m.AttachTracepoint("raw_syscalls:sys_enter", enterTrace); err != nil {
		return errors.Wrap(err, "error attaching to tracepoint")
	}
	if err := m.AttachTracepoint("sched:sched_process_exit", checkExit); err != nil {
		return errors.Wrap(err, "error attaching to tracepoint")
	}

	// Send a signal to the parent process to indicate the compilation has been
	// completed.
	err = parentProcess.Signal(syscall.SIGUSR1)
	if err != nil {
		return err
	}

	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel)
	if err != nil {
		return errors.Wrap(err, "error initializing perf map")
	}

	// Initialize the wait group used to wait for the tracing to be finished.
	wg.Add(1)
	recordSyscalls := false
	go func() {
		var e event
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
			if err != nil {
				logrus.Errorf("failed to decode received data '%s': %s\n", data, err)
				continue
			}
			if e.StopTracing {
				break
			} else {
				name, err := syscallIDtoName(e.ID)
				if err != nil {
					logrus.Errorf("error getting the name for syscall ID %d", e.ID)
				}
				// Syscalls are not recorded until prctl() is called. The first
				// invocation of prctl is guaranteed to happen by the supported
				// OCI runtimes (i.e., runc and crun) as it's being called when
				// setting the seccomp profile.
				if name == "prctl" {
					recordSyscalls = true
				}
				if recordSyscalls {
					syscalls[name]++
				}
			}
		}
		wg.Done()
	}()
	perfMap.Start()
	logrus.Info("PerfMap Start")

	// Waiting for the goroutine which is reading the perf buffer to be done
	// The goroutine will exit when the container exits
	wg.Wait()

	perfMap.Stop()
	logrus.Info("PerfMap Stop")
	if err := generateProfile(syscalls, profilePath, inputFile); err != nil {
		return errors.Wrap(err, "error generating final seccomp profile")
	}
	return nil
}

// generateProfile generates the seccomp profile from the specified syscalls and
// the input file.
func generateProfile(syscalls map[string]int, profilePath string, inputFile string) error {
	outputProfile := types.Seccomp{}
	inputProfile := types.Seccomp{}

	if inputFile != "" {
		input, err := ioutil.ReadFile(inputFile)
		if err != nil {
			return errors.Wrap(err, "error reading input file")
		}
		err = json.Unmarshal(input, &inputProfile)
		if err != nil {
			return errors.Wrap(err, "error parsing input file")
		}
	}

	var names []string
	for syscallName, syscallID := range syscalls {
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
		return errors.Wrap(err, "error writing seccomp profile")
	}
	if err := ioutil.WriteFile(profilePath, sJSON, 0644); err != nil {
		return errors.Wrap(err, "error writing seccomp profile")
	}
	return nil
}

// parseAnnotation parses the provided annotation and extracts the mandatory
// output file and the optional input file.
func parseAnnotation(annotation string) (outputFile string, inputFile string, err error) {
	annotationSplit := strings.Split(annotation, ";")
	if len(annotationSplit) > 2 {
		return "", "", errors.Wrapf(errInvalidAnnotation, "more than one semi-colon: %q", annotation)
	}
	for _, path := range annotationSplit {
		switch {
		// Input profile
		case strings.HasPrefix(path, "if:"):
			inputFile = strings.TrimSpace(strings.TrimPrefix(path, inputPrefix))
			if !filepath.IsAbs(inputFile) {
				return "", "", errors.Wrapf(errInvalidAnnotation, "paths must be absolute: %q", inputFile)
			}
			inputProfile := types.Seccomp{}
			input, err := ioutil.ReadFile(inputFile)
			if err != nil {
				return "", "", errors.Wrapf(errInvalidAnnotation, "error reading input file: %q", inputFile)
			}
			err = json.Unmarshal(input, &inputProfile)
			if err != nil {
				return "", "", errors.Wrapf(errInvalidAnnotation, "error parsing input file: %q", inputFile)
			}

		// Output profile
		case strings.HasPrefix(path, "of:"):
			outputFile = strings.TrimSpace(strings.TrimPrefix(path, outputPrefix))
			if !filepath.IsAbs(outputFile) {
				return "", "", errors.Wrapf(errInvalidAnnotation, "paths must be absolute: %q", inputFile)
			}

		// Unsupported default
		default:
			return "", "", errors.Wrapf(errInvalidAnnotation, "must start %q or %q prefix", inputPrefix, outputPrefix)
		}
	}

	if outputFile == "" {
		return "", "", errors.Wrap(errInvalidAnnotation, "providing output file is mandatory")
	}

	return outputFile, inputFile, nil
}

// syscallIDtoName returns the syscall name for the specified ID.
func syscallIDtoName(id uint32) (string, error) {
	name, err := seccomp.ScmpSyscall(id).GetName()
	return name, err
}

// profileContainsSyscall checks if the input profile contains the syscall..
func profileContainsSyscall(profile *types.Seccomp, syscall string) bool {
	for _, s := range profile.Syscalls {
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
