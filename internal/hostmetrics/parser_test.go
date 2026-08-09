package hostmetrics

import (
	"math"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseProcStatAndCalculateCPU(t *testing.T) {
	previous, err := parseProcStat([]byte("cpu 100 20 30 400 10 5 5 2 0 0\ncpu0 1 2 3 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := parseProcStat([]byte("cpu 150 20 50 500 20 10 10 4 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := calculateCPU(previous, current, "/proc/stat")
	if err != nil {
		t.Fatal(err)
	}
	assertNear(t, status.UserPercent, 50.0/192.0*100)
	assertNear(t, status.SystemPercent, 30.0/192.0*100)
	assertNear(t, status.IdlePercent, 100.0/192.0*100)
	assertNear(t, status.IOWaitPercent, 10.0/192.0*100)
	assertNear(t, status.StealPercent, 2.0/192.0*100)
	assertNear(t, status.TotalBusyPercent, 82.0/192.0*100)
}

func TestCalculateCPURejectsCounterReset(t *testing.T) {
	_, err := calculateCPU(cpuCounters{User: 100}, cpuCounters{User: 99}, "/proc/stat")
	if err == nil || !strings.Contains(err.Error(), "reset or wrapped") {
		t.Fatalf("calculateCPU() error = %v", err)
	}
}

func TestParseMemInfo(t *testing.T) {
	status, err := parseMemInfo([]byte(`MemTotal:       1000 kB
MemAvailable:    250 kB
SwapTotal:       400 kB
SwapFree:        100 kB
Buffers:          10 kB
`), "/proc/meminfo")
	if err != nil {
		t.Fatal(err)
	}
	if status.MemTotalBytes != 1000*1024 || status.MemUsedBytes != 750*1024 || status.SwapUsedBytes != 300*1024 {
		t.Fatalf("status = %#v", status)
	}
	assertNear(t, status.MemAvailablePercent, 25)
}

func TestParsePSI(t *testing.T) {
	status, err := parsePSI([]byte("some avg10=1.25 avg60=2.50 avg300=3.75 total=100\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=10\n"), "/proc/pressure/io")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Availability.Available || !status.Some.Availability.Available || !status.Full.Availability.Available {
		t.Fatalf("status = %#v", status)
	}
	assertNear(t, status.Some.Avg10, 1.25)
	assertNear(t, status.Full.Avg300, 0.30)
}

func TestParsePSIRepresentsMissingFullLine(t *testing.T) {
	status, err := parsePSI([]byte("some avg10=1 avg60=2 avg300=3 total=100\n"), "/proc/pressure/cpu")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Some.Availability.Available || status.Full.Availability.Available || !strings.Contains(status.Full.Availability.Error, "not available") {
		t.Fatalf("status = %#v", status)
	}
}

func TestParseNetDevAndDeterministicOrdering(t *testing.T) {
	data := []byte(`Inter-| Receive | Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
 zeta: 100 10 1 2 0 0 0 0 200 20 3 4 0 0 0 0
 alpha: 300 30 5 6 0 0 0 0 400 40 7 8 0 0 0 0
`)
	counters, err := parseNetDev(data)
	if err != nil {
		t.Fatal(err)
	}
	statuses := networkStatuses(counters, counters, time.Second, "/proc/net/dev")
	if len(statuses) != 2 || statuses[0].Interface != "alpha" || statuses[1].Interface != "zeta" {
		t.Fatalf("statuses = %#v", statuses)
	}
	alpha := counters["alpha"]
	if alpha.RXBytes != 300 || alpha.TXBytes != 400 || alpha.RXDropped != 6 || alpha.TXDropped != 8 {
		t.Fatalf("alpha = %#v", alpha)
	}
}

func TestNetworkRatesRejectCounterReset(t *testing.T) {
	status := NetworkInterfaceStatus{}
	err := applyNetworkRates(&status, networkCounters{RXBytes: 100}, networkCounters{RXBytes: 99}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "reset or wrapped") {
		t.Fatalf("applyNetworkRates() error = %v", err)
	}
}

func TestParseDiskstatsAndRates(t *testing.T) {
	previous, err := parseDiskstats([]byte("8 0 sda 10 0 100 0 20 0 200 0 1 0 300 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := parseDiskstats([]byte("8 0 sda 14 0 140 0 26 0 260 0 2 0 360 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	statuses := diskStatuses(previous, current, 2*time.Second, "/proc/diskstats")
	if len(statuses) != 1 || statuses[0].Name != "sda" || statuses[0].IOInProgress != 2 || statuses[0].WeightedIOMilliseconds != 360 {
		t.Fatalf("statuses = %#v", statuses)
	}
	assertNear(t, statuses[0].ReadsPerSecond, 2)
	assertNear(t, statuses[0].WritesPerSecond, 3)
	assertNear(t, statuses[0].ReadSectorsPerSecond, 20)
	assertNear(t, statuses[0].WriteSectorsPerSecond, 30)
}

func TestDiskRatesRejectCounterReset(t *testing.T) {
	status := DiskStatus{}
	err := applyDiskRates(&status, diskCounters{ReadsCompleted: 10}, diskCounters{ReadsCompleted: 9}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "reset or wrapped") {
		t.Fatalf("applyDiskRates() error = %v", err)
	}
}

func TestFilesystemStatusFromStatfs(t *testing.T) {
	status, err := filesystemStatusFromStatfs("/", syscall.Statfs_t{
		Bsize: 4096, Blocks: 100, Bfree: 25, Bavail: 20, Files: 50, Ffree: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.TotalBytes != 409600 || status.FreeBytes != 102400 || status.AvailableBytes != 81920 {
		t.Fatalf("status = %#v", status)
	}
	assertNear(t, status.UsedPercent, 75)
	assertNear(t, status.FilesUsedPercent, 80)
}

func TestQEMUProcessParsersUseCommandNameOnly(t *testing.T) {
	command, qemu := qemuCommand([]byte("qemu-system-x86\n"))
	if !qemu || command != "qemu-system-x86" {
		t.Fatalf("command/qemu = %q/%t", command, qemu)
	}
	rss, err := parseRSSBytes([]byte("Name:\tqemu-system-x86\nVmRSS:\t123 kB\n"))
	if err != nil || rss != 123*1024 {
		t.Fatalf("rss/error = %d/%v", rss, err)
	}
	ticks, err := parseProcessCPUTicks([]byte("123 (qemu system) S 1 2 3 4 5 6 7 8 9 10 100 20 0 0"))
	if err != nil || ticks != 120 {
		t.Fatalf("ticks/error = %d/%v", ticks, err)
	}
}

func assertNear(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.000001 {
		t.Fatalf("got %.9f, want %.9f", got, want)
	}
}
