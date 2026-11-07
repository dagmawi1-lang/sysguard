"""Reads the collector's CSVs and finds unusual system activity."""
from __future__ import annotations
import csv
import statistics
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

SUSPICIOUS_NAMES = {"xmrig", "minerd", "cpuminer", "nc", "ncat", "netcat", "socat", "hydra", "john", "hashcat", "masscan", "nmap"}
SUSPICIOUS_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")


@dataclass
class Finding:
    rule: str
    severity: str
    start: str
    end: str
    summary: str
    advice: str = ""


@dataclass
class Limits:
    cpu_high: float = 90.0
    mem_high: float = 90.0
    swap_high: float = 50.0
    sustained_samples: int = 3
    proc_cpu_hog: float = 80.0
    proc_hog_samples: int = 3
    process_jump: float = 2.0     # process count vs median baseline
    load_per_core: float = 2.0


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def _runs(rows, pred):
    """Consecutive runs of rows where pred is true."""
    run = []
    for r in rows:
        if pred(r):
            run.append(r)
        elif run:
            yield run; run = []
    if run:
        yield run


def analyze(data_dir: str | Path, limits: Limits | None = None, cores: int = 1) -> tuple[list[Finding], dict]:
    L = limits or Limits()
    d = Path(data_dir)
    sysrows = read_csv(d / "system.csv")
    procs = read_csv(d / "processes.csv")
    events = read_csv(d / "events.csv")
    f: list[Finding] = []
    num = lambda r, k: float(r[k]) if r.get(k) not in (None, "") else 0.0

    for run in _runs(sysrows, lambda r: num(r, "cpu_pct") >= L.cpu_high):
        if len(run) >= L.sustained_samples:
            f.append(Finding("sustained_high_cpu", "warning", run[0]["timestamp"], run[-1]["timestamp"], f"CPU at or above {L.cpu_high:.0f}% for {len(run)} samples (peak {max(num(r, 'cpu_pct') for r in run):.0f}%)", "Check the top processes below for the cause."))
    for run in _runs(sysrows, lambda r: num(r, "mem_used_pct") >= L.mem_high):
        if len(run) >= L.sustained_samples:
            f.append(Finding("memory_pressure", "critical", run[0]["timestamp"], run[-1]["timestamp"], f"Memory {max(num(r, 'mem_used_pct') for r in run):.0f}% used for {len(run)} samples", "Find the process with the highest mem_pct. The system may start killing processes (OOM)."))
    for run in _runs(sysrows, lambda r: num(r, "swap_used_pct") >= L.swap_high):
        f.append(Finding("heavy_swap", "warning", run[0]["timestamp"], run[-1]["timestamp"], f"Swap {max(num(r, 'swap_used_pct') for r in run):.0f}% used", "Heavy swapping makes everything slow. Add RAM or reduce load."))
    for run in _runs(sysrows, lambda r: num(r, "load1") >= L.load_per_core * cores):
        if len(run) >= L.sustained_samples:
            f.append(Finding("high_load", "warning", run[0]["timestamp"], run[-1]["timestamp"], f"Load average {max(num(r, 'load1') for r in run):.1f} on {cores} core(s)", ""))
    counts = [num(r, "process_count") for r in sysrows]
    if len(counts) >= 5:
        base = statistics.median(counts[: max(5, len(counts) // 3)])
        for run in _runs(sysrows, lambda r: num(r, "process_count") >= base * L.process_jump and num(r, "process_count") - base >= 50):
            f.append(Finding("process_explosion", "critical", run[0]["timestamp"], run[-1]["timestamp"], f"Process count jumped to {max(num(r, 'process_count') for r in run):.0f} (baseline {base:.0f})", "Possible fork bomb or runaway script. Look for one parent with many children."))

    # Per-process rules
    by_pid = defaultdict(list)
    for p in procs:
        by_pid[(p["pid"], p["command"])].append(p)
    seen_cmds, first_ts = set(), procs[0]["timestamp"] if procs else None
    for (pid, cmd), rows in by_pid.items():
        hot = [r for r in rows if num(r, "cpu_pct") >= L.proc_cpu_hog]
        if len(hot) >= L.proc_hog_samples:
            f.append(Finding("cpu_hog", "warning", hot[0]["timestamp"], hot[-1]["timestamp"], f"{cmd} (pid {pid}, user {rows[0]['user']}) used ≥{L.proc_cpu_hog:.0f}% CPU in {len(hot)} samples", ""))
        exe = rows[0].get("exe", "") or ""
        name = cmd.lower().split("/")[-1]
        if name in SUSPICIOUS_NAMES or exe.startswith(SUSPICIOUS_DIRS):
            why = "runs from a temporary directory" if exe.startswith(SUSPICIOUS_DIRS) else "matches a known miner/attack tool name"
            f.append(Finding("suspicious_process", "critical", rows[0]["timestamp"], rows[-1]["timestamp"], f"{cmd} (pid {pid}, user {rows[0]['user']}, exe {exe or 'unknown'}) {why}", "Investigate before killing it: note the parent PID, its network connections (ss -tp), and how it started."))
        if rows[0]["timestamp"] != first_ts and cmd not in seen_cmds and num(rows[0], "cpu_pct") >= 20:
            f.append(Finding("new_busy_process", "info", rows[0]["timestamp"], rows[-1]["timestamp"], f"New process {cmd} (pid {pid}) appeared and used {num(rows[0], 'cpu_pct'):.0f}% CPU", ""))
        if rows[0]["timestamp"] == first_ts:
            seen_cmds.add(cmd)
    for e in events:
        if e["kind"] == "listening_ports_changed":
            f.append(Finding("new_listening_port", "warning", e["timestamp"], e["timestamp"], f"Listening ports changed to: {e['detail'].strip() or 'none'}", "A new open port can mean a new service or a backdoor. Check with: ss -ltnp"))

    order = {"critical": 0, "warning": 1, "info": 2}
    f.sort(key=lambda x: (order[x.severity], x.start))
    summary = {
        "samples": len(sysrows),
        "range": (sysrows[0]["timestamp"], sysrows[-1]["timestamp"]) if sysrows else None,
        "cpu_avg": round(statistics.fmean(num(r, "cpu_pct") for r in sysrows), 1) if sysrows else 0,
        "cpu_max": max((num(r, "cpu_pct") for r in sysrows), default=0),
        "mem_avg": round(statistics.fmean(num(r, "mem_used_pct") for r in sysrows), 1) if sysrows else 0,
        "mem_max": max((num(r, "mem_used_pct") for r in sysrows), default=0),
        "top_processes": sorted(((cmd, round(sum(num(r, "cpu_pct") for r in rows) / max(1, len(sysrows)), 1)) for (pid, cmd), rows in by_pid.items()), key=lambda x: -x[1])[:5],
    }
    return f, summary
