package observe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWatchWritesOneValidJSONDocumentPerIteration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	iteration := 0
	summary := WatchSummary{}
	err := Watch(context.Background(), &stdout, WatchOptions{Every: time.Nanosecond, Iterations: 2}, func(context.Context) (ObserveSnapshot, error) {
		iteration++
		return ObserveSnapshot{
			SchemaVersion: SchemaVersion, ObservedAtUTC: "2026-08-09T10:11:12Z",
			WindowID: "window-" + strconv.Itoa(iteration), Duration: "1s", Interval: "1s",
			Victim: Target{Name: "a-web"}, SelectedSuspect: "-", SuspectMode: "victim-only",
		}, nil
	}, &summary)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteWatchSummary(&stderr, summary); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	lines := 0
	for scanner.Scan() {
		lines++
		var snapshot ObserveSnapshot
		if err := json.Unmarshal(scanner.Bytes(), &snapshot); err != nil {
			t.Fatalf("line %d is not JSON: %v\n%s", lines, err, scanner.Text())
		}
		if snapshot.Victim.Name != "a-web" {
			t.Fatalf("line %d victim = %q", lines, snapshot.Victim.Name)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines != 2 || summary.IterationsRun != 2 {
		t.Fatalf("lines=%d summary=%#v", lines, summary)
	}
	if strings.Contains(stdout.String(), "Summary") || !strings.Contains(stderr.String(), "Iterations run: 2") {
		t.Fatalf("stdout/stderr separation failed:\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
	}
}

func TestWatchRejectsInvalidOptions(t *testing.T) {
	collector := func(context.Context) (ObserveSnapshot, error) { return ObserveSnapshot{}, nil }
	for _, options := range []WatchOptions{{}, {Every: time.Second, Iterations: -1}} {
		if err := Watch(context.Background(), &bytes.Buffer{}, options, collector, &WatchSummary{}); err == nil {
			t.Fatalf("options %#v were accepted", options)
		}
	}
}
