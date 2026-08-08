package doctor

import (
	"bytes"
	"strings"
	"testing"
)

func TestOverallResult(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		want   string
	}{
		{"pass ignores skip", Report{Host: []Check{{Status: OK}, {Status: SKIP}}}, "PASS"},
		{"warning", Report{Lab: []Check{{Status: WARN}}}, "WARN"},
		{"failure overrides warning", Report{Host: []Check{{Status: WARN}}, Storage: []Check{{Status: FAIL}}}, "FAIL"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OverallResult(test.report); got != test.want {
				t.Fatalf("OverallResult() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestWriteFormatsSectionsAndRemediation(t *testing.T) {
	report := Report{
		Host: []Check{{Status: OK, Name: "OS is Linux", Detail: "linux"}},
		QEMU: []Check{{
			Status:      WARN,
			Name:        "QEMU process I/O permission",
			Detail:      "qemu io-watch/io-summary require sudo on this host",
			Remediation: qemuSudoRemedy,
		}},
	}
	var output bytes.Buffer
	if err := Write(&output, report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	for _, want := range []string{
		"Solis Doctor",
		"Host checks:",
		"QEMU I/O permission check:",
		"qemu io-watch/io-summary require sudo on this host",
		"run qemu io commands with sudo",
		"Overall result:  WARN",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("doctor output missing %q:\n%s", want, output.String())
		}
	}
}
