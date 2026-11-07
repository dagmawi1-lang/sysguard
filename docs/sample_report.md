# SysGuard monitoring report
_Generated 2026-11-07 02:50_

**60 samples** from 2026-11-07T14:00:00 to 2026-11-07T14:04:55 · CPU avg 35.2% (max 99.0%) · memory avg 52.3% (max 97.5%)

## Findings
- **[CRITICAL] suspicious_process** (14:01:15–14:02:00): kworkerd (pid 9123, user www-data, exe /tmp/.x/kworkerd) runs from a temporary directory  
  _Investigate before killing it: note the parent PID, its network connections (ss -tp), and how it started._
- **[CRITICAL] memory_pressure** (14:02:30–14:02:55): Memory 98% used for 6 samples  
  _Find the process with the highest mem_pct. The system may start killing processes (OOM)._
- **[CRITICAL] process_explosion** (14:03:20–14:03:30): Process count jumped to 3000 (baseline 188)  
  _Possible fork bomb or runaway script. Look for one parent with many children._
- **[CRITICAL] suspicious_process** (14:04:10–14:04:15): nc (pid 8800, user student, exe /usr/bin/nc.openbsd) matches a known miner/attack tool name  
  _Investigate before killing it: note the parent PID, its network connections (ss -tp), and how it started._
- **[WARNING] sustained_high_cpu** (14:01:15–14:02:00): CPU at or above 90% for 10 samples (peak 99%)  
  _Check the top processes below for the cause._
- **[WARNING] cpu_hog** (14:01:15–14:02:00): kworkerd (pid 9123, user www-data) used ≥80% CPU in 10 samples
- **[WARNING] heavy_swap** (14:02:45–14:02:55): Swap 80% used  
  _Heavy swapping makes everything slow. Add RAM or reduce load._
- **[WARNING] sustained_high_cpu** (14:03:20–14:03:30): CPU at or above 90% for 3 samples (peak 99%)  
  _Check the top processes below for the cause._
- **[WARNING] high_load** (14:03:20–14:03:30): Load average 30.0 on 2 core(s)
- **[WARNING] new_listening_port** (14:03:55–14:03:55): Listening ports changed to: 22 631 4444  
  _A new open port can mean a new service or a backdoor. Check with: ss -ltnp_
- **[INFO] new_busy_process** (14:01:15–14:02:00): New process kworkerd (pid 9123) appeared and used 85% CPU

## Busiest processes (average CPU per sample)
| Process | Avg CPU % |
|---|---:|
| kworkerd | 15.0 |
| sshd | 6.5 |
| firefox | 6.3 |
| code | 5.5 |
| systemd-journal | 5.3 |