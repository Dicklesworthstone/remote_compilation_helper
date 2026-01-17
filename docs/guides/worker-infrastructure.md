# Worker Infrastructure Guide

This guide explains what a "worker" is, what kind of machine you need, and how to choose or provision workers for RCH.

## What is a Worker?

A worker is any machine that:
- Is reachable over SSH from your workstation.
- Runs compilation commands on your behalf.
- Returns build artifacts back to your local project.

In practice, a worker is a build server. It can be a cloud VM, an on-prem server, or another workstation on your network.

## Worker Requirements

Minimum requirements:
- Linux machine with SSH access (key-based auth).
- Same CPU architecture as your workstation (e.g., x86_64 -> x86_64, aarch64 -> aarch64).
- Rust toolchain that matches your local nightly (see `rust-toolchain.toml`).
- At least 4 CPU cores.
- At least 8 GB RAM.
- Reliable network connection to your workstation.

Recommended for best performance:
- 8+ CPU cores.
- 16+ GB RAM.
- NVMe SSD.
- Low-latency, high-bandwidth network (LAN or good cloud region proximity).

## Worker Options

Common choices:
- **Cloud VMs**: AWS EC2, GCP Compute, Azure VM.
- **On-prem servers**: spare rack servers or lab machines.
- **Another workstation**: a second dev box on the same LAN.
- **Dedicated build server**: a small cluster or a single powerful machine.

If you already have SSH access to a Linux machine, it can be a worker.

## Cloud VM Recommendations (Ballpark)

These examples are typical in the 8 vCPU range. Pricing varies by region and time, so treat these as rough estimates:
- **AWS**: c6i.2xlarge (8 vCPU) ~ $0.30-$0.40/hr on-demand.
- **GCP**: c2-standard-8 (8 vCPU) ~ $0.30-$0.45/hr on-demand.
- **Azure**: F8s v2 (8 vCPU) ~ $0.30-$0.50/hr on-demand.

Tips:
- Use spot/preemptible instances for cost savings if occasional interruptions are OK.
- Prefer regions close to your workstation to reduce latency.

## Setting Up a Worker (High-Level)

1. **Install Rust nightly** on the worker.
2. **Install RCH worker binary (`rch-wkr`)** on the worker.
3. **Configure SSH access** from your workstation.
4. **Add the worker to RCH** and probe it.

Detailed setup instructions:
- Worker setup and config: `docs/guides/workers.md`
- SSH setup: `docs/guides/ssh-setup.md`

## Multiple Workers

Add more workers when:
- You run multiple agents in parallel.
- Your builds regularly saturate CPU.
- You want redundancy if a worker goes down.

Guidance:
- Start with 1 worker and scale up as needed.
- Prefer a few strong workers over many weak ones.
- Use priorities to steer builds to faster machines.
- Spread workers geographically only if network latency is acceptable.

## Next Steps

- Set up your first worker: `docs/guides/workers.md`
- Validate connectivity: `rch workers probe --all`
- Monitor worker health: `rch status --workers`
