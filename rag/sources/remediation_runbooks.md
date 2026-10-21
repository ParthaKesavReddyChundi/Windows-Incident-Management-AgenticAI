# Standard Operating Procedures & Remediation Runbooks

## Category: Safe Operational Remediation & Mitigation Runbooks
**Source:** ITIL Incident Management & Enterprise SRE Runbooks  
**Tags:** remediation, runbook, allowlist, safety, rollback, risk_level

---

### Section: Runbook RB-01 — Process CPU Throttling
- **Risk Level:** Low
- **Operational Impact:** None to minimal. Target process slows down execution but remains alive.
- **Prerequisites:** Process PID must be confirmed and verified not to be a core Windows system process (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`).

#### Execution Steps
1. Capture current process priority: `(Get-Process -Id <PID>).PriorityClass`.
2. Apply `Idle` or `BelowNormal` priority:
   `Set-Process -Id <PID> -Priority Idle`.
3. Optionally restrict processor affinity to single CPU core:
   `(Get-Process -Id <PID>).ProcessorAffinity = 1`.

#### Verification
Confirm CPU usage of PID drops below 15% within 10 seconds. Check system responsiveness.

#### Rollback Plan
Restore original process priority:
`Set-Process -Id <PID> -Priority Normal`.

---

### Section: Runbook RB-02 — Safe Process Termination
- **Risk Level:** Medium
- **Operational Impact:** Terminates the target process. Any unsaved in-memory state will be lost.
- **Safety Allowlist Rule:** Forbidden to terminate OS critical processes (`svchost.exe` (unless isolated instance), `lsass.exe`, `wininit.exe`, `winlogon.exe`, `explorer.exe`).

#### Execution Steps
1. Send graceful close notification:
   `(Get-Process -Id <PID>).CloseMainWindow()`.
2. Wait 5 seconds. If process remains running, issue termination:
   `Stop-Process -Id <PID> -Force`.

#### Verification
Confirm PID is no longer present in process table:
`Get-Process -Id <PID> -ErrorAction SilentlyContinue` returns null.

#### Rollback Plan
If process is an automatic service, start the service. If it is an interactive application, restart executable from known safe binary path.

---

### Section: Runbook RB-03 — Windows Service Restart & Recovery
- **Risk Level:** Low
- **Operational Impact:** Momentary service unavailability (< 3 seconds) while service restarts.

#### Execution Steps
1. Check current service status:
   `Get-Service -Name <ServiceName>`.
2. Stop the service if hanging in stop_pending or running:
   `Stop-Service -Name <ServiceName> -Force`.
3. Start the service:
   `Start-Service -Name <ServiceName>`.
4. Configure SCM auto-restart:
   `sc.exe failure <ServiceName> reset= 86400 actions= restart/60000/restart/60000/none/0`.

#### Verification
Query service status and verify status is `Running`:
`(Get-Service -Name <ServiceName>).Status -eq "Running"`.

#### Rollback Plan
If service fails to start, inspect Event Log for crash event (Event ID 7000 or 7034). If config was modified, restore previous configuration.

---

### Section: Runbook RB-04 — Memory Working Set Flush
- **Risk Level:** Low (Read-Only Safety Profile)
- **Operational Impact:** None. Windows Memory Manager reclaims unreferenced physical pages.

#### Execution Steps
1. Call Windows kernel memory manager to trim working set for the specified PID:
   ```powershell
   [System.GC]::Collect()
   # Trimming working set via API call
   ```
2. Clear standby list and purge system cache if memory remains constrained.

#### Verification
Verify host available memory increases by at least 100 MB.

---

### Section: Runbook RB-05 — Network Quarantine & Isolation
- **Risk Level:** High (Requires Human Explicit Approval)
- **Operational Impact:** Isolates host from enterprise network; cuts off external connectivity except for local telemetry and management plane.

#### Execution Steps
1. Add temporary outbound block rule:
   `New-NetFirewallRule -DisplayName "IncidentQuarantine-BlockOutbound" -Direction Outbound -Action Block -Profile Any`.
2. Whitelist management subnet and agent port:
   `New-NetFirewallRule -DisplayName "IncidentQuarantine-AllowManagement" -Direction Outbound -Action Allow -RemoteAddress "127.0.0.1"`.

#### Verification
Confirm unauthorized outbound connections are dropped.

#### Rollback Plan
Remove quarantine firewall rules:
`Remove-NetFirewallRule -DisplayName "IncidentQuarantine-*"`
