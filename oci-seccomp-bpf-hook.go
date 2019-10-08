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
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

// ebpfTimout is the timeout in seconds to wait for the child process to signal
// that the eBPF program finished compiling and attached to the tracee.
const ebpfTimeout = 10

// version is the version string of the hook. Set at build time.
var version string

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
			return fmt.Errorf("cannot determine executable path:%q", err.Error())
		}

		process, err := os.StartProcess(executable, []string{"oci-seccomp-bpf-hook", "-r", strconv.Itoa(pid), "-o", outputFile, "-i", inputFile}, attr)
		if err != nil {
			return fmt.Errorf("cannot launch process err: %q", err.Error())
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
			return fmt.Errorf("eBPF program didn't compile and attach within %d seconds", ebpfTimeout)
		}

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
func runBPFSource(pid int, profilePath string, inputFile string) error {
	var wg sync.WaitGroup

	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)

	if err != nil {
		return fmt.Errorf("cannot find the parent process pid %d : %q", ppid, err)
	}

	logrus.Infof("Running floating process PID to attach: %d", pid)
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

	logrus.Info("Loaded tracepoints")

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
				logrus.Errorf("failed to decode received data '%s': %s\n", data, err)
				continue
			}
			if e.StopTracing {
				break
			} else {
				name, err := getName(e.ID)
				if err != nil {
					logrus.Errorf("failed to get name of syscall from id : %d received : %q", e.ID, name)
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
	logrus.Info("PerfMap Start")

	// Waiting for the goroutine which is reading the perf buffer to be done
	// The goroutine will exit when the container exits
	wg.Wait()

	perfMap.Stop()
	logrus.Info("PerfMap Stop")
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
