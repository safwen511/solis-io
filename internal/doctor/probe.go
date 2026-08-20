package doctor

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// Probes contains the read-only host operations used by product doctor. Tests
// may replace individual functions without contacting libvirt or special host
// filesystems.
type Probes struct {
	GOOS          func() string
	EffectiveUID  func() int
	LookPath      func(string) (string, error)
	Stat          func(string) (os.FileInfo, error)
	ReadDir       func(string) ([]os.DirEntry, error)
	OpenReadable  func(string) error
	Access        func(string, uint32) error
	CommandOutput func(string, ...string) ([]byte, error)
}

// effectiveProbes builds effective probes from validated inputs.
func effectiveProbes(custom *Probes) Probes {
	probes := Probes{}
	if custom != nil {
		probes = *custom
	}
	if probes.GOOS == nil {
		probes.GOOS = func() string { return runtime.GOOS }
	}
	if probes.EffectiveUID == nil {
		probes.EffectiveUID = os.Geteuid
	}
	if probes.LookPath == nil {
		probes.LookPath = exec.LookPath
	}
	if probes.Stat == nil {
		probes.Stat = os.Stat
	}
	if probes.ReadDir == nil {
		probes.ReadDir = os.ReadDir
	}
	if probes.OpenReadable == nil {
		probes.OpenReadable = func(path string) error {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			return file.Close()
		}
	}
	if probes.Access == nil {
		probes.Access = syscall.Access
	}
	if probes.CommandOutput == nil {
		probes.CommandOutput = func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		}
	}
	return probes
}
