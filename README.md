# Solis I/O

Solis I/O is a Linux-only provider-side troubleshooting CLI.

It is designed for KVM/libvirt infrastructure owners who need to diagnose
storage latency between tenant VMs without entering guest operating systems
and without reading tenant data.

## Core idea

When a tenant VM becomes slow, Solis should help answer:

- Is the latency caused by the provider infrastructure?
- Is it caused by host block-layer queueing?
- Is it caused by physical device latency?
- Is another VM creating noisy-neighbor I/O pressure?

## Scope

Solis I/O v1 focuses on:

- Linux hosts
- KVM/libvirt
- QEMU VMs
- storage I/O latency
- eBPF block-layer tracing
- full host mode only

Solis does not inspect guest memory, guest filesystems, database contents,
application payloads, or tenant disk contents.

## Planned commands

- solis doctor
- solis inventory
- solis top
- solis inspect <vm>
- solis incidents
- solis explain <incident-id>
