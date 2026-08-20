package guest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const defaultMaxOutputBytes = 256 * 1024

type SSHOptions struct {
	ConnectTimeout time.Duration
	KnownHosts     string
	MaxOutputBytes int
}

// SSHRunner runs only CommandSpec values over OpenSSH in non-interactive mode.
type SSHRunner struct {
	options SSHOptions
}

// NewSSHRunner constructs ssh runner wired to the package's production dependencies.
func NewSSHRunner(options SSHOptions) (*SSHRunner, error) {
	if options.ConnectTimeout <= 0 {
		return nil, errors.New("SSH connect timeout must be positive")
	}
	if strings.TrimSpace(options.KnownHosts) == "" {
		return nil, errors.New("SSH known_hosts path is required")
	}
	if options.MaxOutputBytes <= 0 {
		options.MaxOutputBytes = defaultMaxOutputBytes
	}
	return &SSHRunner{options: options}, nil
}

// Run executes one allowlisted command over SSH without a shell or caller-supplied command text.
func (runner *SSHRunner) Run(ctx context.Context, target Target, command CommandSpec) (Result, error) {
	if target.host == "" || target.user == "" || target.vmName == "" {
		return Result{}, errors.New("SSH target must be resolved from inventory")
	}
	argv, err := command.argv()
	if err != nil {
		return Result{}, err
	}
	args := runner.arguments(target, argv)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdout := newBoundedBuffer(runner.options.MaxOutputBytes)
	stderr := newBoundedBuffer(runner.options.MaxOutputBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if stdout.exceeded || stderr.exceeded {
			return Result{}, fmt.Errorf("guest command %s exceeded output limit", command.Key())
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, fmt.Errorf("guest command %s timed out", command.Key())
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return Result{}, fmt.Errorf("guest command %s failed with exit code %d", command.Key(), exitError.ExitCode())
		}
		return Result{}, fmt.Errorf("guest command %s failed: %w", command.Key(), err)
	}
	if stdout.exceeded || stderr.exceeded {
		return Result{}, fmt.Errorf("guest command %s exceeded output limit", command.Key())
	}
	return Result{Output: stdout.String()}, nil
}

// arguments builds fixed SSH client arguments for the inventory-derived target.
func (runner *SSHRunner) arguments(target Target, argv []string) []string {
	seconds := int((runner.options.ConnectTimeout + time.Second - 1) / time.Second)
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=" + strconv.Itoa(seconds),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + runner.options.KnownHosts,
		"--", target.user + "@" + target.host,
		joinRemoteArgs(argv),
	}
}

// joinRemoteArgs quotes only the already-allowlisted argv used by the remote transport.
func joinRemoteArgs(argv []string) string {
	quoted := make([]string, len(argv))
	for index, argument := range argv {
		// OpenSSH sends one remote command string. Single-quote every fixed argv
		// token and escape embedded quotes so the remote shell cannot reinterpret
		// configured values or the allowlisted SQL text.
		quoted[index] = "'" + strings.ReplaceAll(argument, "'", `'"'"'`) + "'"
	}
	return strings.Join(quoted, " ")
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

// newBoundedBuffer constructs bounded buffer wired to the package's production dependencies.
func newBoundedBuffer(limit int) *boundedBuffer { return &boundedBuffer{limit: limit} }

// Write retains at most the configured diagnostic byte limit and counts discarded bytes.
func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if buffer.buffer.Len()+len(data) > buffer.limit {
		remaining := buffer.limit - buffer.buffer.Len()
		if remaining > 0 {
			_, _ = buffer.buffer.Write(data[:remaining])
		}
		buffer.exceeded = true
		return len(data), nil
	}
	return buffer.buffer.Write(data)
}

// String returns the stable textual representation of the value.
func (buffer *boundedBuffer) String() string { return buffer.buffer.String() }
