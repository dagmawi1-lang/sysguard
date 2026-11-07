# SysGuard roadmap

## Done (v1.0.0)
- [x] Monitor CPU and memory usage (/proc-based, plus swap and load)
- [x] Track running processes (top N with real executable paths)
- [x] Record system events (listening-port changes, login sessions)
- [x] Identify unusual system activity (9 rules)
- [x] Generate monitoring reports (Markdown, HTML with CPU chart), cron-friendly exit codes
- [x] 5 tests including an end-to-end run of the Bash collector

## Next
- [ ] Disk usage and I/O wait (`/proc/diskstats`)
- [ ] Per-process network connections (`ss -tp`) to link suspicious processes to remote IPs
- [ ] systemd timer unit and a log-rotation policy for the CSVs
- [ ] File-integrity checks for `/etc/passwd`, `/etc/sudoers`, and SSH `authorized_keys`
