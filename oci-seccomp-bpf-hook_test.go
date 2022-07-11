package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"runtime"
	"testing"

	types "github.com/containers/common/pkg/seccomp"
	"github.com/stretchr/testify/assert"
)

func TestParseAnnotation(t *testing.T) {
	testProfile := types.Seccomp{}
	testProfile.DefaultAction = types.ActErrno

	tmpFile, err := ioutil.TempFile(os.TempDir(), "input-*.json")
	if err != nil {
		t.Fatalf("cannot create temporary file")
	}
	defer os.Remove(tmpFile.Name())
	testProfileByte, err := json.Marshal(testProfile)
	if err != nil {
		t.Fatalf("cannot marshal json")
	}

	if _, err := tmpFile.Write(testProfileByte); err != nil {
		t.Fatalf("cannot write to the temporary file")
	}

	for _, c := range []struct {
		annotation, input, output string
	}{
		{"if:" + tmpFile.Name() + ";of:/home/test/output.json", tmpFile.Name(), "/home/test/output.json"},
		{"of:/home/test/output.json", "", "/home/test/output.json"},
		{"of:/home/test/output.json;if:" + tmpFile.Name(), tmpFile.Name(), "/home/test/output.json"},
	} {
		output, input, err := parseAnnotation(c.annotation)
		assert.Nil(t, err)
		assert.Equal(t, c.input, input)
		assert.Equal(t, c.output, output)
	}

	// test malformed annotations
	for _, c := range []string{
		"if:/home/test/input1.json;if:/home/test/input2.json;of:/home/test/output.json",
		"if:" + tmpFile.Name(),
		"if:input;of:/home/test/output.json",
		"if:" + tmpFile.Name() + ";of:output",
	} {
		_, _, err := parseAnnotation(c)
		assert.NotNil(t, err)
	}
}
func TestAppendArchIfNotAlreadyIncluded(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("Test runs only reliable on amd64 arch")
	}

	currentArch, err := types.GoArchToSeccompArch(runtime.GOARCH)
	assert.Nil(t, err)
	for _, tc := range []struct {
		profile types.Seccomp
		goArch  string
		expect  func(error, types.Seccomp)
	}{
		{
			profile: types.Seccomp{},
			goArch:  runtime.GOARCH,
			expect: func(err error, profile types.Seccomp) {
				assert.Nil(t, err)
				assert.Len(t, profile.Architectures, 1)
			},
		},
		{
			profile: types.Seccomp{
				Architectures: []types.Arch{currentArch},
			},
			goArch: runtime.GOARCH,
			expect: func(err error, profile types.Seccomp) {
				assert.Nil(t, err)
				assert.Len(t, profile.Architectures, 1)
			},
		},
		{
			profile: types.Seccomp{
				Architectures: []types.Arch{types.ArchMIPS, types.ArchARM},
			},
			goArch: runtime.GOARCH,
			expect: func(err error, profile types.Seccomp) {
				assert.Nil(t, err)
				assert.Len(t, profile.Architectures, 3)
			},
		},
		{
			profile: types.Seccomp{},
			goArch:  "wrong",
			expect: func(err error, profile types.Seccomp) {
				assert.NotNil(t, err)
				assert.Empty(t, profile.Architectures)
			},
		},
	} {
		tc.expect(appendArchIfNotAlreadyIncluded(tc.goArch, &tc.profile), tc.profile)
	}
}
