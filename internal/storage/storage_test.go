package storage

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/safwen511/solis-io/internal/hoststorage"
	"github.com/safwen511/solis-io/internal/inventory"
)

func TestParseBlockStat(t *testing.T) {
	stats, err := parseBlockStat("10 20 30 40 50 60 70 80 90 100 110 120 130 140 150 160 170")
	if err != nil {
		t.Fatalf("parseBlockStat() error = %v", err)
	}
	checks := []struct {
		name string
		got  Counter
		want uint64
	}{
		{"reads completed", stats.ReadsCompleted, 10},
		{"writes completed", stats.WritesCompleted, 50},
		{"sectors read", stats.SectorsRead, 30},
		{"sectors written", stats.SectorsWritten, 70},
		{"I/O in progress", stats.IOInProgress, 90},
		{"I/O time", stats.IOTimeMS, 100},
		{"weighted I/O time", stats.WeightedIOTimeMS, 110},
	}
	for _, check := range checks {
		if !check.got.Available || check.got.Value != check.want {
			t.Errorf("%s = %#v, want available value %d", check.name, check.got, check.want)
		}
	}
}

func TestParseBlockStatRejectsShortLine(t *testing.T) {
	if _, err := parseBlockStat("1 2 3"); err == nil {
		t.Fatal("parseBlockStat() accepted a short line")
	}
}

func TestCalculateDelta(t *testing.T) {
	previous := DeviceStats{
		PhysicalDisk:     "/dev/nvme0n1",
		ReadsCompleted:   knownCounter(100),
		WritesCompleted:  knownCounter(200),
		SectorsRead:      knownCounter(300),
		SectorsWritten:   knownCounter(400),
		IOInProgress:     knownCounter(1),
		IOTimeMS:         knownCounter(600),
		WeightedIOTimeMS: knownCounter(500),
	}
	current := DeviceStats{
		PhysicalDisk:     "/dev/nvme0n1",
		ReadsCompleted:   knownCounter(120),
		WritesCompleted:  knownCounter(240),
		SectorsRead:      knownCounter(4396),
		SectorsWritten:   knownCounter(8592),
		IOInProgress:     knownCounter(3),
		IOTimeMS:         knownCounter(1600),
		WeightedIOTimeMS: knownCounter(550),
	}

	delta, err := CalculateDelta(previous, current, 2*time.Second)
	if err != nil {
		t.Fatalf("CalculateDelta() error = %v", err)
	}
	if delta.ReadsPerSecond.Value != 10 || delta.WritesPerSecond.Value != 20 {
		t.Fatalf("operation rates = %#v, want 10 reads/s and 20 writes/s", delta)
	}
	if delta.ReadMiBPerSecond.Value != 1 || delta.WriteMiBPerSecond.Value != 2 {
		t.Fatalf("MiB rates = %#v, want 1 MiB/s read and 2 MiB/s write", delta)
	}
	if delta.IOInProgress.Value != 3 || delta.IOTimeDeltaMS.Value != 1000 || delta.WeightedIODeltaMS.Value != 50 {
		t.Fatalf("gauge/deltas = %#v, want io in progress 3, io delta 1000, weighted delta 50", delta)
	}
	if delta.UtilPercent.Value != 50 || !delta.UtilPercent.Available {
		t.Fatalf("UtilPercent = %#v, want 50%%", delta.UtilPercent)
	}
}

func TestCalculateDeltaRejectsCounterReset(t *testing.T) {
	previous := DeviceStats{ReadsCompleted: knownCounter(10)}
	current := DeviceStats{ReadsCompleted: knownCounter(5)}

	delta, err := CalculateDelta(previous, current, time.Second)
	if err != nil {
		t.Fatalf("CalculateDelta() error = %v", err)
	}
	if delta.ReadsPerSecond.Available {
		t.Fatalf("ReadsPerSecond = %#v, want unavailable after reset", delta.ReadsPerSecond)
	}
}

func TestCaptureSortsAndDeduplicatesPhysicalDisks(t *testing.T) {
	victims := []inventory.VM{
		{Name: "a-web", Tenant: "tenant-a", Role: "web", Disk: "/images/a-web.qcow2"},
		{Name: "a-db", Tenant: "tenant-a", Role: "db", Disk: "/images/a-db.qcow2"},
	}
	suspect := inventory.VM{Name: "b-stress", Tenant: "tenant-b", Role: "stress", Disk: "/images/b-stress.qcow2"}
	resolve := func(path string) hoststorage.Mapping {
		physical := "/dev/sdb,/dev/nvme0n1"
		if strings.Contains(path, "a-db") {
			physical = "/dev/nvme0n1"
		}
		return hoststorage.Mapping{DiskPath: path, PhysicalDisk: physical}
	}
	read := func(disk string) DeviceStats {
		return DeviceStats{PhysicalDisk: disk, ReadsCompleted: knownCounter(1)}
	}

	snapshot := captureWith("tenant-a", "b-stress", victims, suspect, resolve, read)
	if len(snapshot.Targets) != 3 || snapshot.Targets[0].VM.Name != "a-db" || snapshot.Targets[2].VM.Name != "b-stress" {
		t.Fatalf("Targets = %#v, want sorted victims followed by suspect", snapshot.Targets)
	}
	if len(snapshot.Devices) != 2 || snapshot.Devices[0].PhysicalDisk != "/dev/nvme0n1" || snapshot.Devices[1].PhysicalDisk != "/dev/sdb" {
		t.Fatalf("Devices = %#v, want sorted unique physical disks", snapshot.Devices)
	}
}

func TestWatchLayerSamplesNormalizesAndDeduplicates(t *testing.T) {
	targets := []VMTarget{
		{Storage: hoststorage.Mapping{
			SourceDevice: "/dev/mapper/vg-lv",
			ParentDevice: "/dev/nvme0n1p3",
			PhysicalDisk: "/dev/nvme0n1",
		}},
		{Storage: hoststorage.Mapping{
			SourceDevice: "/dev/mapper/vg-lv",
			ParentDevice: "/dev/nvme0n1p3",
			PhysicalDisk: "/dev/nvme0n1",
		}},
	}
	normalize := func(device string) string {
		if device == "/dev/mapper/vg-lv" {
			return "/dev/dm-1"
		}
		return device
	}
	read := func(device string) DeviceStats { return DeviceStats{PhysicalDisk: device} }

	samples := watchLayerSamplesWith(targets, normalize, read)
	if len(samples) != 3 {
		t.Fatalf("len(samples) = %d, want one source, parent, and physical row", len(samples))
	}
	want := []layerSample{
		{LayerType: "source", Device: "/dev/dm-1", Stats: DeviceStats{PhysicalDisk: "/dev/dm-1"}},
		{LayerType: "parent", Device: "/dev/nvme0n1p3", Stats: DeviceStats{PhysicalDisk: "/dev/nvme0n1p3"}},
		{LayerType: "physical", Device: "/dev/nvme0n1", Stats: DeviceStats{PhysicalDisk: "/dev/nvme0n1"}},
	}
	for i := range want {
		if samples[i].LayerType != want[i].LayerType || samples[i].Device != want[i].Device {
			t.Errorf("samples[%d] = %#v, want %#v", i, samples[i], want[i])
		}
	}
}

func TestWriteSnapshotFormatsUnavailableValues(t *testing.T) {
	if got := counterText(Counter{}); got != "-" {
		t.Fatalf("counterText() = %q, want - for unavailable counter", got)
	}

	snapshot := Snapshot{
		VictimSelector:  "tenant-a",
		SuspectSelector: "b-stress",
		Targets: []VMTarget{{
			TargetType: "victim",
			VM: inventory.VM{
				Name:    "a-db",
				Tenant:  "tenant-a",
				Role:    "db",
				QEMUPID: "1234",
				Disk:    "/images/a-db.qcow2",
			},
			Storage: hoststorage.Mapping{
				SourceDevice: "/dev/mapper/vg-lv",
				ParentDevice: "/dev/nvme0n1p3",
				PhysicalDisk: "/dev/nvme0n1",
			},
		}},
		Devices: []DeviceStats{{PhysicalDisk: "/dev/nvme0n1"}},
	}

	var output bytes.Buffer
	if err := Write(&output, snapshot); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	for _, expected := range []string{
		"Storage Snapshot",
		"VM storage targets",
		"/dev/mapper/vg-lv",
		"/dev/nvme0n1p3",
		"Host device snapshot",
		"WEIGHTED_IO_TIME_MS",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("snapshot missing %q:\n%s", expected, output.String())
		}
	}
}
