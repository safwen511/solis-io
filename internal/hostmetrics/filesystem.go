package hostmetrics

import (
	"errors"
	"math"
	"syscall"
)

// filesystemStatusFromStatfs builds filesystem status from statfs and returns an error when
// validation or source access fails.
func filesystemStatusFromStatfs(mountpoint string, stat syscall.Statfs_t) (FilesystemStatus, error) {
	blockSize := uint64(stat.Bsize)
	total, overflow := multiplyUint64(stat.Blocks, blockSize)
	if overflow {
		return FilesystemStatus{}, errors.New("filesystem total byte count overflow")
	}
	free, overflow := multiplyUint64(stat.Bfree, blockSize)
	if overflow {
		return FilesystemStatus{}, errors.New("filesystem free byte count overflow")
	}
	available, overflow := multiplyUint64(stat.Bavail, blockSize)
	if overflow {
		return FilesystemStatus{}, errors.New("filesystem available byte count overflow")
	}
	usedPercent := 0.0
	if total > 0 && free <= total {
		usedPercent = float64(total-free) / float64(total) * 100
	}
	filesUsedPercent := 0.0
	if stat.Files > 0 && stat.Ffree <= stat.Files {
		filesUsedPercent = float64(stat.Files-stat.Ffree) / float64(stat.Files) * 100
	}
	return FilesystemStatus{
		Mountpoint: mountpoint, Availability: measured(mountpoint), TotalBytes: total,
		FreeBytes: free, AvailableBytes: available, UsedPercent: usedPercent,
		FilesTotal: stat.Files, FilesFree: stat.Ffree, FilesUsedPercent: filesUsedPercent,
	}, nil
}

// multiplyUint64 builds multiply uint64 from validated inputs.
func multiplyUint64(left, right uint64) (uint64, bool) {
	if left != 0 && right > math.MaxUint64/left {
		return 0, true
	}
	return left * right, false
}
