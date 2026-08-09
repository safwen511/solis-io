package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCollectPSIUnavailableDoesNotAbort(t *testing.T) {
	status := collectPSI(func(path string) ([]byte, error) {
		return nil, os.ErrPermission
	}, Options{CollectPSI: true, ProcRoot: "/fixture/proc"})
	if status.Availability.Available || status.CPU.Availability.Available || !strings.Contains(status.Availability.Error, "permission denied") {
		t.Fatalf("status = %#v", status)
	}
}

func TestCollectQEMUProcessesReadsNoArgumentsOrEnvironment(t *testing.T) {
	procRoot := t.TempDir()
	for _, pid := range []string{"10", "20"} {
		if err := os.Mkdir(filepath.Join(procRoot, pid), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	data := map[string][]byte{
		filepath.Join(procRoot, "10", "comm"):   []byte("qemu-system-x86\n"),
		filepath.Join(procRoot, "10", "status"): []byte("VmRSS: 123 kB\n"),
		filepath.Join(procRoot, "10", "stat"):   []byte("10 (qemu system) S 1 2 3 4 5 6 7 8 9 10 100 20\n"),
		filepath.Join(procRoot, "20", "comm"):   []byte("sshd\n"),
	}
	var reads []string
	readFile := func(path string) ([]byte, error) {
		reads = append(reads, path)
		value, ok := data[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return value, nil
	}
	section := collectQEMUProcesses(readFile, os.ReadDir, procRoot)
	if len(section.Processes) != 1 || section.Processes[0].PID != 10 || section.Processes[0].Command != "qemu-system-x86" {
		t.Fatalf("section = %#v", section)
	}
	if section.Processes[0].RSSBytes == nil || *section.Processes[0].RSSBytes != 123*1024 || section.Processes[0].CPUTicks == nil || *section.Processes[0].CPUTicks != 120 {
		t.Fatalf("process = %#v", section.Processes[0])
	}
	for _, path := range reads {
		if strings.HasSuffix(path, "cmdline") || strings.HasSuffix(path, "environ") {
			t.Fatalf("unsafe procfs read: %s", path)
		}
	}
}

func TestCollectWithPartialFailuresReturnsHostStatus(t *testing.T) {
	status, err := collectWith(Options{
		Interval: time.Second, CollectPSI: true, CollectNetwork: true,
		Mountpoints: []string{"/missing"}, ProcRoot: "/fixture/proc", SysRoot: "/fixture/sys",
	}, dependencies{
		readFile: func(string) ([]byte, error) { return nil, os.ErrPermission },
		readDir:  func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission },
		statfs:   func(string, *syscall.Statfs_t) error { return os.ErrPermission },
		hostname: func() (string, error) { return "fixture-host", nil },
		now:      func() time.Time { return time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC) },
		sleep:    func(time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.Availability.Available || status.CPU.Availability.Available || status.Memory.Availability.Available || status.Disks.Availability.Available || status.NetworkInterfaces.Availability.Available || status.QEMUProcesses.Availability.Available {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Filesystems.Mounts) != 1 || status.Filesystems.Mounts[0].Availability.Available {
		t.Fatalf("filesystems = %#v", status.Filesystems)
	}
	if status.Hostname != "fixture-host" || status.ObservedAtUTC != "2026-08-09T20:00:00Z" {
		t.Fatalf("identity = %#v", status)
	}
}

func TestCollectWithCompleteFixtureCalculatesWindowedRates(t *testing.T) {
	procRoot := t.TempDir()
	sysRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "pressure"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysRoot, "class", "block", "sda"), 0o700); err != nil {
		t.Fatal(err)
	}
	sequence := map[string][][]byte{
		filepath.Join(procRoot, "stat"): {
			[]byte("cpu 100 0 100 800 0 0 0 0\n"),
			[]byte("cpu 120 0 110 870 0 0 0 0\n"),
		},
		filepath.Join(procRoot, "diskstats"): {
			[]byte("8 0 sda 10 0 100 0 20 0 200 0 0 0 300\n"),
			[]byte("8 0 sda 12 0 120 0 24 0 240 0 0 0 340\n"),
		},
		filepath.Join(procRoot, "net", "dev"): {
			[]byte("eth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n"),
			[]byte("eth0: 300 3 0 0 0 0 0 0 600 6 0 0 0 0 0 0\n"),
		},
		filepath.Join(procRoot, "meminfo"):                    {[]byte("MemTotal: 1000 kB\nMemAvailable: 500 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")},
		filepath.Join(procRoot, "sys", "kernel", "osrelease"): {[]byte("fixture-kernel\n")},
	}
	for _, resource := range []string{"cpu", "memory", "io"} {
		sequence[filepath.Join(procRoot, "pressure", resource)] = [][]byte{[]byte("some avg10=0 avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0\n")}
	}
	indexes := make(map[string]int)
	readFile := func(path string) ([]byte, error) {
		values, ok := sequence[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		index := indexes[path]
		if index >= len(values) {
			index = len(values) - 1
		}
		indexes[path]++
		return values[index], nil
	}
	status, err := collectWith(Options{
		Interval: time.Second, CollectPSI: true, CollectNetwork: true,
		Mountpoints: []string{"/"}, ProcRoot: procRoot, SysRoot: sysRoot,
	}, dependencies{
		readFile: readFile,
		readDir:  os.ReadDir,
		statfs: func(string, *syscall.Statfs_t) error {
			return nil
		},
		hostname: func() (string, error) { return "fixture-host", nil },
		now:      func() time.Time { return time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC) },
		sleep:    func(time.Duration) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || !status.CPU.Availability.Available || status.KernelRelease != "fixture-kernel" {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Disks.Devices) != 1 || status.Disks.Devices[0].ReadsPerSecond != 2 || status.Disks.Devices[0].WriteSectorsPerSecond != 40 {
		t.Fatalf("disks = %#v", status.Disks)
	}
	if len(status.NetworkInterfaces.Interfaces) != 1 || status.NetworkInterfaces.Interfaces[0].RXBytesPerSecond != 200 || status.NetworkInterfaces.Interfaces[0].TXBytesPerSecond != 400 {
		t.Fatalf("network = %#v", status.NetworkInterfaces)
	}
}

func TestCollectRejectsInvalidOptions(t *testing.T) {
	_, err := collectWith(Options{}, dependencies{})
	if err == nil || !strings.Contains(err.Error(), "interval must be positive") {
		t.Fatalf("collectWith() error = %v", err)
	}
}
