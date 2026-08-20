# Contributing to Solis I/O

Solis is an experimental observability tool with strict evidence-honesty and
privacy boundaries. Changes must preserve those boundaries and keep the code
understandable to an operator reviewing a provider-side incident.

## Function comments

Every named function needs a concise comment that explains its contract. Good
comments focus on information that is not obvious from syntax:

- why the function exists and which invariant it enforces;
- whether it reads or mutates host, guest, or filesystem state;
- resource ownership and cleanup responsibilities;
- how unavailable or partial evidence is represented;
- verifier, kernel-layout, privilege, and boundedness constraints in eBPF code;
- privacy constraints, especially why raw pointers, process arguments,
  environments, payloads, SQL text, table data, guest files, and secrets cannot
  cross an output boundary.

Exported Go comments start with the declared identifier. Tests describe the
regression or invariant they protect. Shell comments identify remote effects
and script-owned cleanup paths. Python workload functions use docstrings. Avoid
comments that only restate the function name or narrate individual statements.

`go test ./...` includes a repository check that rejects newly undocumented Go,
shell, Python, jq, or eBPF C functions.

## Generated eBPF object

Comments in `internal/ebpf/bpf/vm_block_latency.bpf.c` can change debug line
metadata. After editing that file, regenerate the authentic embedded ELF with
the documented Docker generator. Never create a placeholder object and never
remove the authentic generated object.

## Validation

Before handing off a change, run the formatting, module verification, Go test,
build, shell syntax, Python compile, and `git diff --check` commands documented
in [README.md](README.md). Leave unrelated working-tree changes intact.
