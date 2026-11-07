#!/usr/bin/env bash
# SysGuard collector: samples CPU, memory, load, processes, logins, and listening ports from /proc and
# standard tools into CSV files that sysguard (Python) analyzes. Linux only; no root required.
#
# usage: ./collect.sh [-i INTERVAL_SECONDS] [-n SAMPLES] [-o OUTPUT_DIR] [-t TOP_N_PROCESSES]
set -euo pipefail

INTERVAL=5
SAMPLES=12
OUT="sysguard_data"
TOPN=15

usage() { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while getopts ":i:n:o:t:h" opt; do
  case "$opt" in
    i) INTERVAL="$OPTARG" ;;
    n) SAMPLES="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    t) TOPN="$OPTARG" ;;
    h) usage 0 ;;
    *) echo "unknown option -$OPTARG" >&2; usage 2 ;;
  esac
done
for v in INTERVAL SAMPLES TOPN; do
  [[ "${!v}" =~ ^[0-9]+$ && "${!v}" -gt 0 ]] || { echo "error: $v must be a positive integer" >&2; exit 2; }
done
[[ -r /proc/stat && -r /proc/meminfo ]] || { echo "error: /proc not available (SysGuard's collector needs Linux)" >&2; exit 1; }

mkdir -p "$OUT"
SYS="$OUT/system.csv"; PROC="$OUT/processes.csv"; EVT="$OUT/events.csv"
[[ -s "$SYS" ]]  || echo "timestamp,cpu_pct,mem_used_pct,swap_used_pct,load1,process_count" > "$SYS"
[[ -s "$PROC" ]] || echo "timestamp,pid,ppid,user,cpu_pct,mem_pct,command,exe" > "$PROC"
[[ -s "$EVT" ]]  || echo "timestamp,kind,detail" > "$EVT"

# Prints "total idle" jiffies from the aggregate cpu line.
cpu_jiffies() { awk '/^cpu /{idle=$5+$6; t=0; for(i=2;i<=NF;i++) t+=$i; print t, idle; exit}' /proc/stat; }

mem_stats() {
  awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2}
       END{ mu=(t>0)?100*(t-a)/t:0; su=(st>0)?100*(st-sf)/st:0; printf "%.1f,%.1f", mu, su }' /proc/meminfo
}

listening_ports() {
  if command -v ss >/dev/null 2>&1; then ss -H -ltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -n -u | tr '\n' ' '
  elif [[ -r /proc/net/tcp ]]; then awk 'NR>1 && $4=="0A"{split($2,a,":"); printf "%d\n", strtonum("0x" a[2])}' /proc/net/tcp 2>/dev/null | sort -n -u | tr '\n' ' '
  fi
}

csv_escape() { local s=${1//\"/\"\"}; printf '"%s"' "$s"; }

prev_ports=""
read -r prev_total prev_idle < <(cpu_jiffies)
sleep 1
for ((s = 1; s <= SAMPLES; s++)); do
  ts=$(date '+%Y-%m-%dT%H:%M:%S')
  read -r total idle < <(cpu_jiffies)
  dt=$((total - prev_total)); di=$((idle - prev_idle))
  cpu=$(awk -v dt="$dt" -v di="$di" 'BEGIN{ printf "%.1f", (dt>0)?100*(dt-di)/dt:0 }')
  prev_total=$total; prev_idle=$idle
  load1=$(cut -d' ' -f1 /proc/loadavg)
  nproc_count=$(find /proc -maxdepth 1 -regex '/proc/[0-9]+' 2>/dev/null | wc -l)
  echo "$ts,$cpu,$(mem_stats),$load1,$nproc_count" >> "$SYS"

  # Top processes by CPU. exe is resolved from /proc/PID/exe when readable (it can show binaries run from /tmp).
  ps -eo pid=,ppid=,user=,pcpu=,pmem=,comm= --sort=-pcpu 2>/dev/null | head -n "$TOPN" | while read -r pid ppid user pcpu pmem comm; do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    echo "$ts,$pid,$ppid,$(csv_escape "$user"),$pcpu,$pmem,$(csv_escape "$comm"),$(csv_escape "$exe")" >> "$PROC"
  done

  ports=$(listening_ports || true)
  if [[ -n "$prev_ports" && "$ports" != "$prev_ports" ]]; then
    echo "$ts,listening_ports_changed,$(csv_escape "$ports")" >> "$EVT"
  elif [[ $s -eq 1 ]]; then
    echo "$ts,listening_ports,$(csv_escape "$ports")" >> "$EVT"
  fi
  prev_ports=$ports
  if [[ $s -eq 1 ]] && command -v who >/dev/null 2>&1; then
    who 2>/dev/null | while read -r line; do echo "$ts,login_session,$(csv_escape "$line")" >> "$EVT"; done
  fi

  printf '\r[sysguard] sample %d/%d  cpu %5s%%  mem %s' "$s" "$SAMPLES" "$cpu" "$(mem_stats | cut -d, -f1)%" >&2
  if [[ $s -lt $SAMPLES ]]; then sleep "$INTERVAL"; fi
done
echo >&2
echo "Wrote $SYS, $PROC, $EVT"
