package storagevm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSysfsDeviceResolverClassifiesLayers(t *testing.T) {
	root := t.TempDir()
	sysDev := filepath.Join(root, "dev", "block")
	sysClass := filepath.Join(root, "class", "block")
	if err := os.MkdirAll(sysDev, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		id, name, uuid, kind string
	}{
		{id: "252:0", name: "dm-0", uuid: "LVM-test", kind: "lvm"},
		{id: "253:0", name: "dm-1", uuid: "CRYPT-test", kind: "dmcrypt"},
		{id: "259:0", name: "nvme0n1", kind: "physical"},
		{id: "8:0", name: "sda", kind: "physical"},
		{id: "7:0", name: "loop0", kind: "unknown"},
		{id: "9:0", name: "md0", kind: "unknown"},
		{id: "251:0", name: "zram0", kind: "unknown"},
		{id: "43:0", name: "nbd0", kind: "unknown"},
		{id: "240:0", name: "mystery0", kind: "unknown"},
	} {
		deviceRoot := filepath.Join(sysClass, test.name)
		if err := os.MkdirAll(deviceRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if test.uuid != "" {
			if err := os.MkdirAll(filepath.Join(deviceRoot, "dm"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(deviceRoot, "dm", "uuid"), []byte(test.uuid+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(deviceRoot, filepath.Join(sysDev, test.id)); err != nil {
			t.Fatal(err)
		}
	}
	resolver := sysfsDeviceResolver{sysDevRoot: sysDev, sysClassRoot: sysClass}
	for _, test := range []struct {
		id, name, kind string
	}{
		{id: "252:0", name: "dm-0", kind: "lvm"},
		{id: "253:0", name: "dm-1", kind: "dmcrypt"},
		{id: "259:0", name: "nvme0n1", kind: "physical"},
		{id: "8:0", name: "sda", kind: "physical"},
		{id: "7:0", name: "loop0", kind: "unknown"},
		{id: "9:0", name: "md0", kind: "unknown"},
		{id: "251:0", name: "zram0", kind: "unknown"},
		{id: "43:0", name: "nbd0", kind: "unknown"},
		{id: "240:0", name: "mystery0", kind: "unknown"},
	} {
		got := resolver.Resolve(test.id)
		if got.DeviceName != test.name || got.SourcePath != "/dev/"+test.name || got.LayerKind != test.kind {
			t.Errorf("Resolve(%q) = %#v", test.id, got)
		}
	}
}
