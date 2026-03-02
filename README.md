# Warden-eBPF: Zero-Trust Container Breakout Detector

Warden-eBPF is a lightweight, low-level security observability tool built with C and Python. It leverages eBPF (Extended Berkeley Packet Filter) to monitor file system access at the Linux kernel level, specifically targeting and mitigating container breakout attempts via misconfigured bind mounts.

## Theoretical Background & Research

Before building this tool, I researched how container isolation (Namespaces, Cgroups, Chroot) actually works under the hood and how a simple bind mount misconfiguration can lead to a complete host compromise. 

Read my full deep-dive research and the breakout methodology on Medium: 
**[Insert Your Medium Article Link Here]**

## System Architecture

The architecture is designed to completely bypass user-space manipulation by operating directly within the kernel. It consists of three core components:

1. **The eBPF Sensor (C):** Hooks into the `sys_enter_openat` kernel tracepoint. It safely extracts the PID, command name, and target file path directly from memory using `bpf_probe_read_user_str`, and submits the data to a BPF Perf Ring Buffer.
2. **The Rule Engine (Python):** Parses a `security_rules.yaml` file to determine restricted host paths (e.g., `/host_root/etc/shadow`).
3. **Active Mitigation & Logging:** If a process attempts to open a restricted host file, the Python daemon intercepts the event, immediately sends a `SIGKILL` to the offending PID, and generates a structured JSON audit log.

## Features

* Kernel-level syscall tracing via eBPF Tracepoints
* Zero-overhead monitoring without in-container agents
* YAML-based dynamic rule configuration
* Active threat mitigation via immediate process termination
* Structured JSON audit logging for SIEM integration

## Quick Start

Ensure you have BCC tools and Linux headers installed on your system.

```bash
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-yaml
