# 🖥️ SysGuard — Linux system monitoring utility

A **Bash collector** samples CPU, memory, swap, load, processes, logins, and listening ports straight from `/proc` and standard tools. A **Python analyzer** then finds unusual activity: crypto-miners in `/tmp`, memory leaks, fork bombs, CPU hogs, attack tools, and newly opened ports. It writes Markdown or HTML reports.

**Languages:** Bash · Python (standard library)
**Shows:** Linux internals (`/proc/stat` jiffies, `/proc/meminfo`, `/proc/PID/exe`, `ss`), shell scripting, and monitoring and detection logic.

## Quick start
```bash
./collect.sh -i 5 -n 60 -o sysguard_data        # 5 minutes of samples (Linux; no root needed)
python3 -m sysguard analyze sysguard_data --report report.html

python3 -m sysguard sample demo_data            # synthetic data with 6 injected incidents
python3 -m sysguard analyze demo_data --cores 2
python3 -m pytest -q                            # 5 tests, including a live run of collect.sh
```
`analyze` exits with **code 2 when it finds something critical**, so it can run from cron and alert you:
`*/10 * * * * cd ~/SysGuard && ./collect.sh -n 10 -i 30 && python3 -m sysguard analyze sysguard_data || notify-send "SysGuard alert"`

## How the collector works (`collect.sh`)
- **CPU %**: reads total and idle jiffies from `/proc/stat` twice and computes `100 × (Δtotal − Δidle) / Δtotal`. This is the same method `top` uses.
- **Memory / swap**: `MemTotal − MemAvailable` from `/proc/meminfo`, the correct "really used" number (it ignores cache).
- **Processes**: `ps -eo pid,ppid,user,pcpu,pmem,comm` plus `readlink /proc/PID/exe` to see *where the binary really lives*. Malware often renames itself (for example `kworkerd`) but runs from `/tmp`.
- **Ports**: `ss -ltn`, with a fallback to parsing `/proc/net/tcp`. Logs an event when the set of listening ports changes.
- `set -euo pipefail`, argument validation, safe CSV quoting, and appending to existing files.

## Detection rules (`sysguard/analyze.py`)
| Rule | Signal |
|---|---|
| `suspicious_process` | binary in `/tmp`, `/var/tmp`, `/dev/shm`, or a known miner/attack-tool name (xmrig, nc, hydra…) |
| `process_explosion` | process count ≥ 2× baseline and +50 (fork bomb) |
| `memory_pressure` / `heavy_swap` | ≥90% memory for 3 samples / ≥50% swap |
| `sustained_high_cpu` / `high_load` | ≥90% CPU for 3 samples / load ≥ 2 × cores |
| `cpu_hog` | one process ≥80% CPU for 3 samples |
| `new_listening_port` | listening-port set changed (e.g. a new `4444`) |
| `new_busy_process` | a process absent at the start that is now using ≥20% CPU |

On the synthetic data, every injected incident is reported, and the clean version reports nothing. See `docs/sample_report.md`.

## License

**Permission required.** © 2026 Dagmawi Melaku. You need my written permission before using, copying, or modifying this code, and any approved use must credit me with a link to this repository. Viewing, forking on GitHub, and running it to judge or review a submission are allowed without asking. To ask, [open an issue](../../issues/new). See [LICENSE](LICENSE) for the full terms.
