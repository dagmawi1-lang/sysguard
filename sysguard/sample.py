"""Writes synthetic collector output with known incidents, for demos and tests."""
from __future__ import annotations
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


def write_sample(out: str | Path, samples: int = 60, incidents: bool = True, seed: int = 3) -> Path:
    rnd = random.Random(seed)
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    t0 = datetime(2026, 11, 7, 14, 0, 0)
    sysw = csv.writer((out / "system.csv").open("w", newline="")); sysw.writerow(["timestamp", "cpu_pct", "mem_used_pct", "swap_used_pct", "load1", "process_count"])
    pw = csv.writer((out / "processes.csv").open("w", newline="")); pw.writerow(["timestamp", "pid", "ppid", "user", "cpu_pct", "mem_pct", "command", "exe"])
    ew = csv.writer((out / "events.csv").open("w", newline="")); ew.writerow(["timestamp", "kind", "detail"])
    normal = [(812, 1, "student", "firefox", "/usr/lib/firefox/firefox"), (640, 1, "student", "code", "/usr/share/code/code"), (301, 1, "root", "sshd", "/usr/sbin/sshd"), (455, 1, "root", "systemd-journal", "/usr/lib/systemd/systemd-journald")]
    for i in range(samples):
        ts = (t0 + timedelta(seconds=5 * i)).isoformat()
        cpu, mem, swap, load, nproc = rnd.uniform(5, 30), rnd.uniform(40, 55), 0.0, rnd.uniform(0.2, 0.9), rnd.randint(180, 195)
        procs = [(pid, pp, u, rnd.uniform(0, 12), rnd.uniform(1, 9), c, e) for pid, pp, u, c, e in normal]
        if incidents:
            if 15 <= i < 25:   # crypto-miner dropped in /tmp
                cpu = rnd.uniform(94, 99); load = rnd.uniform(3.5, 4.5)
                procs.append((9123, 1, "www-data", rnd.uniform(85, 97), 2.0, "kworkerd", "/tmp/.x/kworkerd"))
            if 30 <= i < 36:   # memory leak
                mem = 90 + (i - 30) * 1.5; swap = 20 + (i - 30) * 12
                procs.append((7002, 640, "student", 15.0, 40 + (i - 30) * 6, "python3", "/usr/bin/python3"))
            if 40 <= i < 43:   # fork bomb
                nproc = 1200 + (i - 40) * 900; cpu = 99; load = 30
            if i == 47:
                ew.writerow([ts, "listening_ports_changed", "22 631 4444"])
            if 50 <= i < 52:
                procs.append((8800, 301, "student", 0.5, 0.1, "nc", "/usr/bin/nc.openbsd"))
        if i == 0:
            ew.writerow([ts, "listening_ports", "22 631"])
        sysw.writerow([ts, f"{cpu:.1f}", f"{mem:.1f}", f"{swap:.1f}", f"{load:.2f}", nproc])
        for p in sorted(procs, key=lambda x: -x[3]):
            pw.writerow([ts, p[0], p[1], p[2], f"{p[3]:.1f}", f"{p[4]:.1f}", p[5], p[6]])
    return out
