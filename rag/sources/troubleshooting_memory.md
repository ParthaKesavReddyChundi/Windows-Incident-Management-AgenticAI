# Windows Memory Anomaly Troubleshooting Guide

## Category: Memory Pressure & Memory Leaks
**Source:** Windows Systems Administration & SRE Runbooks  
**Tags:** memory, ram, paging_file, memory_leak, poolmon, working_set, committed_bytes

---

### Section: Memory Exhaustion Overview
Severe memory pressure occurs when the combined working sets of active processes and kernel memory allocations exceed total physical RAM, forcing the Windows Memory Manager to aggressively page memory to disk (`pagefile.sys`), leading to severe system degradation and thrashing.

#### Common Symptoms
- Available memory drops below 500 MB (or < 10% of physical RAM).
- System disk I/O surges dramatically as the pagefile is heavily read from and written to.
- Applications crash with `STATUS_NO_MEMORY` (0xC0000017) or "Out of Memory" exceptions.
- Kernel emits Event ID 2004 (`Windows successfully diagnosed a low memory condition`).

#### Key Performance Metrics
- `memory_percent`: Percent of total physical RAM in use.
- `memory_available_bytes`: Bytes of physical memory immediately available for allocation.
- `Paging File: % Usage`: Percentage of the pagefile currently in use. A sustained value > 75% indicates dangerous commitment pressure.
- `Memory: Pages/sec`: The rate at which pages are read from or written to disk to resolve hard page faults. Sustained > 500 pages/sec signals severe thrashing.

---

### Section: Application Memory Leaks
An application continuously allocates dynamic memory (heap or virtual memory) and fails to release or de-reference it, causing its private working set and committed bytes to monotonically increase over time.

#### Root Causes
- Unreleased native heap allocations (e.g. `malloc` / `new` without corresponding `free` / `delete`).
- Leaked event handlers or uncollected static object graphs in managed runtimes (.NET / C#).
- Resource leaks such as unclosed Windows OS handles (file handles, socket handles, thread handles, event objects).

#### Diagnostic Procedure
1. Inspect `process_collector` telemetry to examine the top memory consumers sorted by `memory_info.rss` (Resident Set Size) and `memory_percent`.
2. Check `num_handles` for each top process. If handle count is steadily growing past 10,000, a handle leak is co-occurring with the memory leak.
3. Compare the process's current memory consumption against its baseline working set.
4. Review Windows Event Log `Application` channel for Event ID 1000 crashes indicating memory allocation failures.

#### Remediation Actions
1. **Trim Working Set (Read-Only / Safe Maintenance):** Instruct the Windows Memory Manager to flush the process's working set pages to standby cache or paging file via Windows API `SetProcessWorkingSetSize(-1, -1)`. This reclaims RAM without stopping the application.
2. **Graceful Application Restart (Medium Risk):** If the leaked application is a non-critical worker or secondary service, initiate a graceful restart to purge all allocated virtual memory.
3. **Emergency Process Termination (High Risk):** If the memory leak threatens host stability and available RAM is < 200 MB, terminate the runaway process (`Stop-Process -Id <PID> -Force`).
4. **Increase Pagefile Ceiling (System Config):** Expand system pagefile dynamically to prevent hard system crashes while the application bug is resolved.

---

### Section: Kernel Pool Leaks (Paged & Non-Paged Pool)
Kernel-mode drivers allocating memory from the Paged Pool or Non-Paged Pool without releasing it. Unlike user-mode leaks, kernel memory leaks cannot be resolved by terminating a user process; they degrade the entire operating system until a reboot or driver reload.

#### Root Causes
- Third-party antivirus, network filter, or storage drivers leaking kernel pool tags.
- High network socket churn without socket closure exhausting Non-Paged Pool.

#### Diagnostic Procedure
1. Observe `Memory: Pool Nonpaged Bytes`. If it exceeds 500 MB (or > 10% of total RAM), a driver leak is highly probable.
2. Run `poolmon.exe` from Windows Driver Kit or execute `Get-WmiObject Win32_OperatingSystem | Select-Object TotalVirtualMemorySize, FreeVirtualMemory`.
3. Locate the top tag with the highest difference between `Allocs` and `Frees`.

#### Remediation Actions
1. Identify the leaking driver module associated with the pool tag.
2. Restart the parent Windows service or unbind the network filter driver.
3. Update or reinstall the faulty device driver.
