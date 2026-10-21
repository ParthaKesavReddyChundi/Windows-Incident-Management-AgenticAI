# Windows CPU Anomaly Troubleshooting Guide

## Category: CPU Performance & Runaway Processes
**Source:** Windows Systems Administration & SRE Runbooks  
**Tags:** cpu, performance, runaway_process, throttling, core_affinity, wmi_spikes

---

### Section: High CPU Utilization Overview
Sustained total CPU utilization exceeding 85% across multiple collection intervals indicates resource exhaustion, unhandled infinite execution loops, CPU-bound cryptographic operations, or hardware interruption storms (DPCs/ISRs).

#### Common Symptoms
- Total CPU usage exceeds 90% continuously for more than 60 seconds.
- Interactive user interface freezes, sluggish mouse/keyboard responsiveness.
- Task Manager shows individual processes consuming 100% of a single core or maxing out multi-core capacity.
- Elevated thread context switching (> 100,000 switches/sec).

#### Key Performance Metrics
- `cpu_percent`: Overall host processor load percentage.
- `cpu_percent_per_core`: Vector of utilization for each logical core.
- `Process.cpu_percent`: Individual process processor usage.
- `System: Processor Queue Length`: Number of threads ready for execution but waiting for a processor. A value > 2 per core indicates severe bottleneck.

---

### Section: Runaway Worker Processes
A single rogue or malfunctioning application thread consuming excessive clock cycles without yielding CPU execution time.

#### Root Causes
- Infinite loops in user application code (e.g. while(true) without sleep or asynchronous yield).
- Stuck garbage collection cycles or heap compaction in managed runtimes (.NET, Java, Node.js).
- High-volume data parsing or regex catastrophic backtracking.
- Rogue background cryptocurrency miner malware (e.g. xmrig masquerading under system names).

#### Diagnostic Procedure
1. Identify the top CPU-consuming process ID (PID) and executable name using `process_collector` telemetry.
2. Check process command-line arguments and parent process ID (PPID) to determine if it was launched legitimately or via an unexpected shell (cmd.exe / powershell.exe).
3. Inspect thread activity within the process using `Get-Process -Id <PID> | Select-Object -ExpandProperty Threads`.
4. Check whether CPU consumption is evenly distributed across all logical cores or isolated to a single core thread.

#### Remediation Actions
1. **Throttle Process Priority (Low Risk):** Lower the base priority of the process to `BelowNormal` or `Idle` using `Set-Process -Id <PID> -Priority Idle`. This immediately yields CPU to OS and critical services without killing the process.
2. **Restrict CPU Core Affinity (Low Risk):** Restrict the process to execute on a single core (e.g. Core 0) via `(Get-Process -Id <PID>).ProcessorAffinity = 0x0001` to prevent host starvation.
3. **Graceful Process Termination (Medium Risk):** Issue a graceful close request (`CloseMainWindow()`) to allow the process to save state.
4. **Forced Process Termination (Medium/High Risk):** Terminate the rogue PID using `Stop-Process -Id <PID> -Force` if the process is unresponsive and non-critical.
5. **Rollback & Verification:** Monitor host CPU % for 15 seconds after action; verify CPU % drops below 50%.

---

### Section: WMI Provider Host (WmiPrvSE.exe) High CPU
`WmiPrvSE.exe` is the Windows Management Instrumentation Provider Service. When it consumes high CPU, it is usually responding to poorly written or high-frequency WMI queries from monitoring tools or malicious scripts.

#### Root Causes
- External monitoring agent querying WMI classes at excessive intervals (< 1s).
- Corrupted WMI repository.
- Malicious persistence scripts polling WMI event subscriptions.

#### Diagnostic Procedure
1. Open Event Viewer and navigate to `Applications and Services Logs -> Microsoft -> Windows -> WMI-Activity -> Operational`.
2. Locate Event ID 5858 (WMI query error) or inspect Event ID 5861 to find the `ClientProcessId` triggering the query.
3. Cross-reference `ClientProcessId` to determine the offending application.

#### Remediation Actions
1. Restart the WMI service: `Restart-Service winmgmt -Force`.
2. If WMI repository is corrupted, verify consistency: `winmgmt /verifyrepository`.
3. If necessary, salvage the repository: `winmgmt /salvagerepository`.
