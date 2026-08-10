package ebpf

import (
	"math"
	"time"
)

// The last bucket is open-ended. Assignment uses strict upper bounds, so a
// request at exactly 100 us belongs to the <250 us bucket.
var vmBlockLatencyBucketUpperNS = [...]uint64{
	uint64(100 * time.Microsecond),
	uint64(250 * time.Microsecond),
	uint64(500 * time.Microsecond),
	uint64(time.Millisecond),
	uint64(2 * time.Millisecond),
	uint64(5 * time.Millisecond),
	uint64(10 * time.Millisecond),
	uint64(20 * time.Millisecond),
	uint64(50 * time.Millisecond),
	uint64(100 * time.Millisecond),
	uint64(250 * time.Millisecond),
	uint64(500 * time.Millisecond),
	uint64(time.Second),
	math.MaxUint64,
}

var vmBlockLatencyBucketLabels = [...]string{
	"<100 us",
	"<250 us",
	"<500 us",
	"<1 ms",
	"<2 ms",
	"<5 ms",
	"<10 ms",
	"<20 ms",
	"<50 ms",
	"<100 ms",
	"<250 ms",
	"<500 ms",
	"<1 s",
	"1 s+",
}

type boundedVMBlockLatencyHistogram struct {
	count   uint64
	totalNS uint64
	minNS   uint64
	maxNS   uint64
	buckets [len(vmBlockLatencyBucketUpperNS)]uint64
}

func (histogram *boundedVMBlockLatencyHistogram) observe(latencyNS uint64) {
	if histogram.count == 0 || latencyNS < histogram.minNS {
		histogram.minNS = latencyNS
	}
	if latencyNS > histogram.maxNS {
		histogram.maxNS = latencyNS
	}
	histogram.count++
	if math.MaxUint64-histogram.totalNS < latencyNS {
		histogram.totalNS = math.MaxUint64
	} else {
		histogram.totalNS += latencyNS
	}
	for index, upper := range vmBlockLatencyBucketUpperNS {
		if latencyNS < upper || index == len(vmBlockLatencyBucketUpperNS)-1 {
			histogram.buckets[index]++
			return
		}
	}
}

func (histogram boundedVMBlockLatencyHistogram) summary() (minimum, average, p50, p95, p99, maximum float64) {
	if histogram.count == 0 {
		return 0, 0, 0, 0, 0, 0
	}
	return nsToMS(histogram.minNS),
		nsToMS(histogram.totalNS) / float64(histogram.count),
		histogram.percentile(0.50),
		histogram.percentile(0.95),
		histogram.percentile(0.99),
		nsToMS(histogram.maxNS)
}

func (histogram boundedVMBlockLatencyHistogram) percentile(value float64) float64 {
	if histogram.count == 0 {
		return 0
	}
	rank := uint64(math.Ceil(value * float64(histogram.count)))
	if rank == 0 {
		rank = 1
	}
	var cumulative uint64
	for index, count := range histogram.buckets {
		cumulative += count
		if cumulative < rank {
			continue
		}
		if index == len(histogram.buckets)-1 {
			return nsToMS(histogram.maxNS)
		}
		return nsToMS(vmBlockLatencyBucketUpperNS[index])
	}
	return nsToMS(histogram.maxNS)
}

func (histogram boundedVMBlockLatencyHistogram) publicBuckets() []VMBlockLatencyHistogramBucket {
	buckets := make([]VMBlockLatencyHistogramBucket, len(vmBlockLatencyBucketLabels))
	for index, label := range vmBlockLatencyBucketLabels {
		percent := 0.0
		if histogram.count > 0 {
			percent = float64(histogram.buckets[index]) / float64(histogram.count) * 100
		}
		buckets[index] = VMBlockLatencyHistogramBucket{
			Range: label, Count: histogram.buckets[index], Percent: percent,
		}
	}
	return buckets
}

func nsToMS(value uint64) float64 {
	return float64(value) / float64(time.Millisecond)
}

func operationSummary(device, operation string, histogram boundedVMBlockLatencyHistogram) VMBlockLatencyDeviceOperation {
	minimum, average, p50, p95, p99, maximum := histogram.summary()
	return VMBlockLatencyDeviceOperation{
		Device: device, Operation: operation, Count: histogram.count,
		TotalLatencyMS: nsToMS(histogram.totalNS),
		LatencyMinMS:   minimum, LatencyAvgMS: average, LatencyP50MS: p50,
		LatencyP95MS: p95, LatencyP99MS: p99, LatencyMaxMS: maximum,
		PercentilesApproximate: histogram.count > 0,
		Histogram:              histogram.publicBuckets(),
	}
}
