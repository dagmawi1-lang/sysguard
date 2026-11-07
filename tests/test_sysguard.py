import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sysguard.__main__ import main
from sysguard.analyze import Limits, analyze
from sysguard.sample import write_sample

ROOT = Path(__file__).resolve().parents[1]


def test_detects_every_injected_incident(tmp_path):
    findings, summary = analyze(write_sample(tmp_path / "d"), cores=2)
    rules = {f.rule for f in findings}
    assert {"suspicious_process", "memory_pressure", "process_explosion", "sustained_high_cpu", "cpu_hog", "heavy_swap", "high_load", "new_listening_port"} <= rules
    sus = [f for f in findings if f.rule == "suspicious_process"]
    assert any("/tmp/" in f.summary for f in sus) and any(" nc " in f" {f.summary} " for f in sus)
    assert findings[0].severity == "critical"
    assert summary["samples"] == 60 and summary["cpu_max"] >= 99


def test_clean_system_is_quiet(tmp_path):
    findings, _ = analyze(write_sample(tmp_path / "c", incidents=False), cores=2)
    assert findings == []


def test_thresholds_are_tunable(tmp_path):
    d = write_sample(tmp_path / "t", incidents=False)
    findings, _ = analyze(d, Limits(cpu_high=10, sustained_samples=2), cores=2)
    assert any(f.rule == "sustained_high_cpu" for f in findings)


def test_cli_exit_codes_and_reports(tmp_path, capsys):
    d = write_sample(tmp_path / "x")
    assert main(["analyze", str(d), "--report", str(tmp_path / "r.html"), "--cores", "2"]) == 2, "critical findings → exit 2 (useful in cron/CI)"
    html = (tmp_path / "r.html").read_text()
    assert "<svg" in html and "kworkerd" in html
    clean = write_sample(tmp_path / "y", incidents=False)
    assert main(["analyze", str(clean), "--cores", "2"]) == 0
    assert main(["analyze", str(tmp_path / "missing")]) == 1


@pytest.mark.skipif(not Path("/proc/stat").exists() or shutil.which("bash") is None, reason="collector needs Linux /proc")
def test_bash_collector_end_to_end(tmp_path):
    out = tmp_path / "live"
    r = subprocess.run([str(ROOT / "collect.sh"), "-i", "1", "-n", "2", "-o", str(out)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    rows = list(csv.DictReader((out / "system.csv").open()))
    assert len(rows) == 2 and 0 <= float(rows[0]["cpu_pct"]) <= 100 and float(rows[0]["mem_used_pct"]) > 0
    procs = list(csv.DictReader((out / "processes.csv").open()))
    assert procs and all(p["pid"].isdigit() for p in procs)
    # Appending a second run keeps one header.
    subprocess.run([str(ROOT / "collect.sh"), "-i", "1", "-n", "1", "-o", str(out)], capture_output=True, timeout=30, check=True)
    assert (out / "system.csv").read_text().count("timestamp,") == 1
    bad = subprocess.run([str(ROOT / "collect.sh"), "-n", "zero"], capture_output=True, text=True)
    assert bad.returncode == 2 and "positive integer" in bad.stderr
    findings, _ = analyze(out, cores=os.cpu_count() or 1)
    assert isinstance(findings, list)
