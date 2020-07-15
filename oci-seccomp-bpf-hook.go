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
	"os/exec"
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
	// BPFTimeout is the timeout in seconds to wait for the child process to signal
	// that the eBPF program finished compiling and attached to the tracee.
	BPFTimeout = 10
	// InputPrefix is the prefix for input files in the runtime annotation.
	InputPrefix = "if:"
	// OutputPrefix is the prefix for output files in the runtime annotation.
	OutputPrefix = "of:"
	// HookAnnotation is the runtime-spec annotation used to start and run
	// the hook by passing arguments.
	HookAnnotation = "io.containers.trace-syscall"
)

var (
	// version is the version string of the hook. Set at build time.
	version string
	// errInvalidAnnotation denotes an error for an invalid runtime annotation.
	errInvalidAnnotation = errors.New("invalid annotation")
)

func main() {
	// To facilitate debugging of the hook, write all logs to the syslog,
	// so we can inspect its output via `journalctl`.
	if hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		logrus.AddHook(hook)
	}

	runBPF := flag.Int("r", 0, "Trace the specified PID")
	outputFile := flag.String("o", "", "Path of the output file")
	inputFile := flag.String("i", "", "Path of the input file")
	start := flag.Bool("s", false, "Start tracing and read the state spec from stdin")
	printVersion := flag.Bool("version", false, "Print the version")
	flag.Parse()

	// Validate input.
	if *outputFile != "" {
		if !filepath.IsAbs(*outputFile) {
			logrus.Fatal("Output filepath is not absolute")
		}
	}
	if *inputFile != "" {
		if !filepath.IsAbs(*inputFile) {
			logrus.Fatal("Input filepath is not absolute")
		}
	}

	// Execute commands.
	var err error
	switch {
	case *printVersion:
		fmt.Println(version)
	case *runBPF > 0:
		err = runBPFSource(*runBPF, *outputFile, *inputFile)
	case *start:
		logrus.Infof("Started OCI seccomp hook version %s", version)
		err = detachAndTrace()
	default:
		logrus.Fatalf("Unsupported arguments: %v", os.Args)
	}

	if err != nil {
		logrus.Fatalf("%v: please refer to the syslog (e.g., journalctl(1)) for more details", err)
	}
}

// modprobe the specified module.
func modprobe(module string) error {
	bin, err := exec.LookPath("modprobe")
	if err != nil {
		// Fallback to `/usr/sbin/modprobe`.  The environment may be
		// empty.  If that doesn't exist either, we'll fail below.
		bin = "/usr/sbin/modprobe"
	}
	return exec.Command(bin, module).Run()
}

// detachAndTrace re-executes the current executable to "fork" in go-ish way and
// traces the provided PID.
func detachAndTrace() error {
	logrus.Info("Loading kheaders module")
	if err := modprobe("kheaders"); err != nil {
		return errors.Wrap(err, "error loading kheaders module")
	}

	// Read the State spec from stdin and unmarshal it.
	var s spec.State
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&s); err != nil {
		return err
	}

	// Sanity check the PID.
	if s.Pid <= 0 {
		return errors.Errorf("invalid PID %d (must be greater than 0)", s.Pid)
	}

	// Parse the State's annotation.
	annotation := s.Annotations[HookAnnotation]
	outputFile, inputFile, err := parseAnnotation(annotation)
	if err != nil {
		return err
	}

	// We are running as a hook and are hence blocking the container
	// (engine) from running. Go doesn't allow for forking, so we are using
	// a common trick in go land and execute ourselves and exit.  This way,
	// we're passing the arguments (i.e., the PID) to the child process
	// which can start tracing.
	//
	// We're waiting at most for `BPFTimeout` seconds for a SIGUSR1 from
	// the child to signal they compiled and started the BPF program
	// successfully. Otherwise, we're shooting down the child process and
	// return an error.
	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil,
			nil,
		},
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2)

	executable, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "cannot determine executable")
	}

	process, err := os.StartProcess(executable, []string{"oci-seccomp-bpf-hook", "-r", strconv.Itoa(s.Pid), "-o", outputFile, "-i", inputFile}, attr)
	if err != nil {
		return errors.Wrap(err, "cannot re-execute")
	}
	defer func() {
		if err := process.Release(); err != nil {
			logrus.Errorf("Error releasing process: %v", err)
		}
	}()

	select {
	// Check which signal we received and act accordingly.
	case s := <-sig:
		logrus.Infof("Received signal (presumably from child): %v", s)
		switch s {
		case syscall.SIGUSR1:
			// Child started tracing. We can safely detach.
			break
		case syscall.SIGUSR2:
			return errors.New("error while tracing")
		default:
			return errors.Errorf("unexpected signal %v", s)
		}

	// The timeout kicked in. Kill the child and return the sad news.
	case <-time.After(BPFTimeout * time.Second):
		if err := process.Kill(); err != nil {
			logrus.Errorf("error killing child process: %v", err)
		}
		return errors.Errorf("BPF program didn't compile and attach within %d seconds", BPFTimeout)
	}

	return nil
}

// run the BPF source and attach it to raw_syscalls:sys_enter tracepoint
func runBPFSource(pid int, profilePath string, inputFile string) (finalErr error) {
	var wg sync.WaitGroup

	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)
	if err != nil {
		return errors.Wrapf(err, "cannot find parent process %d", ppid)
	}
	logrus.Infof("Running floating process PID to attach: %d", pid)

	signaledParent := false
	defer func() {
		if !signaledParent && finalErr != nil {
			logrus.Infof("Sending SIGUSR2 to parent (%d)", ppid)
			if err := parentProcess.Signal(syscall.SIGUSR2); err != nil {
				logrus.Errorf("error sending signal to parent process: %v", err)
			}
		}
	}()

	syscalls := make(map[string]int, 303)
	src := strings.Replace(source, "$PARENT_PID", strconv.Itoa(pid), -1)
	m := bcc.NewModule(src, []string{})
	defer m.Close()

	logrus.Info("Loading enter tracepoint")
	enterTrace, err := m.LoadTracepoint("enter_trace")
	if err != nil {
		return errors.Wrap(err, "error loading tracepoint")
	}
	logrus.Info("Loading exit tracepoint")
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

	// Send a signal to the parent process to indicate the compilation has
	// been completed.
	if err := parentProcess.Signal(syscall.SIGUSR1); err != nil {
		return err
	}
	signaledParent = true

	table := bcc.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		return errors.Wrap(err, "error initializing perf map")
	}

	// Initialize the wait group used to wait for the tracing to be finished.
	wg.Add(1)
	go func() {
		defer wg.Done()
		recordSyscalls := false
		var e event
		for data := range channel {
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e); err != nil {
				// Return in case of an error. Otherwise, we
				// could miss stop event and run into an
				// infinite loop.
				logrus.Errorf("failed to decode received data %q: %s\n", data, err)
				return
			}

			// The BPF program is done tracing, so we can stop
			// reading from the perf buffer.
			if e.StopTracing {
				return
			}

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
	}()
	logrus.Info("PerfMap Start")
	perfMap.Start()

	// Waiting for the goroutine which is reading the perf buffer to be done
	// The goroutine will exit when the container exits
	wg.Wait()
	logrus.Info("BPF progam has finished")

	logrus.Info("PerfMap Stop")
	perfMap.Stop()

	logrus.Infof("Writing seccomp profile to %q", profilePath)
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
			if !syscallInProfile(&inputProfile, syscallName) {
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
			inputFile = strings.TrimSpace(strings.TrimPrefix(path, InputPrefix))
			if !filepath.IsAbs(inputFile) {
				return "", "", errors.Wrapf(errInvalidAnnotation, "Input file path must be absolute: %q", inputFile)
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
			outputFile = strings.TrimSpace(strings.TrimPrefix(path, OutputPrefix))
			if !filepath.IsAbs(outputFile) {
				return "", "", errors.Wrapf(errInvalidAnnotation, "Output file path must be absolute: %q", outputFile)
			}

		// Unsupported default
		default:
			return "", "", errors.Wrapf(errInvalidAnnotation, "must start %q or %q prefix", InputPrefix, OutputPrefix)
		}
	}

	if outputFile == "" {
		return "", "", errors.Wrap(errInvalidAnnotation, "providing output file is mandatory")
	}

	return outputFile, inputFile, nil
}

// syscallIDtoName returns the syscall name for the specified ID.
func syscallIDtoName(id uint32) (string, error) {
	return seccomp.ScmpSyscall(id).GetName()
}

// syscallInProfile checks if the input profile contains the syscall..
func syscallInProfile(profile *types.Seccomp, syscall string) bool {
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
