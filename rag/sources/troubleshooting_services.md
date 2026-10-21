# Windows Service & Process Failure Troubleshooting Guide

## Category: Windows Services & Application Crashes
**Source:** Windows Systems Administration & Enterprise SRE Runbooks  
**Tags:** service, crash, eventlog, spooler, wuauserv, sc_failure, recovery_action

---

### Section: Critical Windows Service Failures Overview
Windows Services run in the background to provide core operating system functions (networking, security, update management, spooling). When an automatic or critical service crashes, stops unexpectedly, or enters a hung state, system capabilities and security baselines degrade immediately.

#### Common Symptoms
- Windows Service Control Manager (SCM) logs Event ID 7034 (`The service terminated unexpectedly`) or Event ID 7031 (`The service crashed N times`).
- A core system service (e.g., `Spooler`, `wuauserv`, `EventLog`, `LanmanServer`) is found in the `STOPPED` state despite being configured for `AUTOMATIC` startup.
- Dependent services fail to start, producing Event ID 7001 (`The service depends on another service which failed to start`).
- Application hangs with Event ID 1002 in the Application log.

#### Key Performance Metrics
- `service_collector` status: Service state (`RUNNING`, `STOPPED`, `START_PENDING`, `STOP_PENDING`, `PAUSED`).
- Windows Event Log records: Frequency of Event IDs 7034, 7036, 7040, 1000, 1002.

---

### Section: Unhandled Service Crash & Termination (Event ID 7034)
A service process encounters an unhandled exception (Access Violation 0xC0000005, Stack Overflow 0xC00000FD), causing the operating system to terminate the hosting executable.

#### Root Causes
- Memory corruption in third-party native service DLLs.
- Exhaustion of system resources (GDI objects, handles, memory) preventing initialization.
- File system permission corruption on service working directory or configuration registry keys.
- Malicious tampering: An attacker purposefully killing defender, logging, or monitoring services (defense evasion).

#### Diagnostic Procedure
1. Check `service_collector` telemetry to identify which service changed status from `RUNNING` to `STOPPED`.
2. Inspect Windows Event Viewer `System` log for Event ID 7034:
   Look for the specific service name (e.g. `Spooler`, `Dnscache`, `wuauserv`).
3. Inspect Windows Event Viewer `Application` log for corresponding Event ID 1000:
   Identify the `Faulting application name`, `Faulting module name`, and `Exception code`.
4. Check service startup type:
   `Get-Service -Name <ServiceName> | Select-Object Name, Status, StartType`.

#### Remediation Actions
1. **Service Recovery Restart (Low Risk):** Attempt an immediate restart of the stopped service:
   `Start-Service -Name <ServiceName>` or `Restart-Service -Name <ServiceName> -Force`.
2. **Configure SCM Failure Recovery Policy (Low Risk):** Instruct Windows Service Control Manager to automatically restart the service upon failure:
   `sc.exe failure <ServiceName> reset= 86400 actions= restart/60000/restart/60000/none/0`.
3. **Verify Service Binary Integrity (Read-Only):** Run System File Checker on the hosting executable:
   `sfc /verifyfile="C:\Windows\System32\<service_binary>.exe"`.
4. **Inspect Service Account Permissions (Low Risk):** Verify the service account (e.g., `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, or `LocalSystem`) has read/execute rights to the service binary.
5. **Rollback & Verification:** Check `Get-Service -Name <ServiceName>` after 10 seconds to confirm the service remains in the `RUNNING` state.
