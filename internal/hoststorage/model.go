// Package hoststorage resolves file paths to their host filesystem and block devices.
package hoststorage

// Mapping describes the host storage backing a VM disk file.
type Mapping struct {
	DiskPath     string
	Mountpoint   string
	SourceDevice string
	Filesystem   string
	ParentDevice string
	PhysicalDisk string
}
