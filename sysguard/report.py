from __future__ import annotations
import html
from datetime import datetime


def markdown(findings, summary) -> str:
    rng = summary["range"] or ("—", "—")
    out = ["# SysGuard monitoring report", f"_Generated {datetime.now():%Y-%m-%d %H:%M}_", "",
           f"**{summary['samples']} samples** from {rng[0]} to {rng[1]} · CPU avg {summary['cpu_avg']}% (max {summary['cpu_max']}%) · memory avg {summary['mem_avg']}% (max {summary['mem_max']}%)", "",
           "## Findings"]
    out += [f"- **[{x.severity.upper()}] {x.rule}** ({x.start[11:19]}–{x.end[11:19]}): {x.summary}" + (f"  \n  _{x.advice}_" if x.advice else "") for x in findings] or ["No unusual activity detected."]
    out += ["", "## Busiest processes (average CPU per sample)", "| Process | Avg CPU % |", "|---|---:|"] + [f"| {c} | {v} |" for c, v in summary["top_processes"]]
    return "\n".join(out)


def html_report(findings, summary, cpu_series=None) -> str:
    e = html.escape
    col = {"critical": "#cf222e", "warning": "#9a6700", "info": "#0969da"}
    rows = "".join(f"<tr><td><span style='background:{col[x.severity]};color:#fff;border-radius:99px;padding:2px 8px;font-size:11px'>{x.severity}</span></td><td>{e(x.rule)}</td><td>{e(x.summary)}<br><small>{e(x.advice)}</small></td><td>{e(x.start[11:19])}–{e(x.end[11:19])}</td></tr>" for x in findings)
    chart = ""
    if cpu_series:
        n = len(cpu_series); pts = " ".join(f"{i / max(1, n - 1) * 600:.1f},{100 - v:.1f}" for i, v in enumerate(cpu_series))
        chart = f"<h2>CPU %</h2><svg viewBox='0 0 600 100' width='100%' height='140' preserveAspectRatio='none' role='img' aria-label='CPU usage over time'><line x1=0 y1=10 x2=600 y2=10 stroke='#cf222e55' stroke-dasharray='4'/><polyline fill='none' stroke='#2f81f7' stroke-width='1.5' points='{pts}'/></svg>"
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>SysGuard report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1000px;margin:auto;padding:24px;background:#0d1117;color:#e6edf3}}table{{width:100%;border-collapse:collapse;background:#161b22}}td,th{{padding:8px;border-bottom:1px solid #30363d;text-align:left;font-size:13px;vertical-align:top}}small{{color:#8b949e}}svg{{background:#161b22;border-radius:8px}}</style></head>
<body><h1>🖥️ SysGuard report</h1><p><small>{summary['samples']} samples · CPU avg {summary['cpu_avg']}% · memory avg {summary['mem_avg']}%</small></p>{chart}
<h2>Findings</h2><table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Time</th></tr>{rows or '<tr><td colspan=4>No unusual activity.</td></tr>'}</table></body></html>"""
