import argparse
import os
import sys
from pathlib import Path

from .analyze import Limits, analyze, read_csv
from .report import html_report, markdown
from .sample import write_sample


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sysguard", description="Analyze SysGuard collector output for unusual system activity")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("data_dir"); a.add_argument("--report", help="write .md or .html report"); a.add_argument("--cpu-high", type=float, default=90.0); a.add_argument("--cores", type=int, default=os.cpu_count() or 1)
    s = sub.add_parser("sample", help="write synthetic data with known incidents"); s.add_argument("out"); s.add_argument("--clean", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "sample":
        write_sample(args.out, incidents=not args.clean); print(f"Synthetic data written to {args.out}"); return 0
    if not (Path(args.data_dir) / "system.csv").exists():
        print(f"No system.csv in {args.data_dir}. Run ./collect.sh first.", file=sys.stderr); return 1
    findings, summary = analyze(args.data_dir, Limits(cpu_high=args.cpu_high), cores=args.cores)
    print(markdown(findings, summary))
    if args.report:
        cpu = [float(r["cpu_pct"]) for r in read_csv(Path(args.data_dir) / "system.csv")]
        Path(args.report).write_text(html_report(findings, summary, cpu) if args.report.endswith(".html") else markdown(findings, summary))
        print(f"\nReport written to {args.report}")
    return 2 if any(f.severity == "critical" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
