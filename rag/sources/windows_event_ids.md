# Windows Security & System Event IDs Reference Guide

## Category: Windows Event Log Forensic Triage
**Source:** Microsoft Windows Event Log Specifications & Security Auditing Baselines  
**Tags:** event_log, event_id, security, system, application, audit, authentication, crash

---

### Section: Event ID 7034 & 7036 — Service Control Manager Events
- **Log Channel:** System
- **Source:** Service Control Manager
- **Severity:** Error (7034), Information (7036)

#### Event ID 7034 Description
`The <ServiceName> service terminated unexpectedly. It has done this N time(s).`
Indicates that a background Windows service halted without sending a standard stop control code to the SCM. Typically caused by an unhandled access violation, an out-of-memory condition, or process termination via Taskkill.

#### Forensic Analysis
Cross-reference the timestamp with Event ID 1000 in the Application log to identify the crash address and faulting module. Check if service was stopped manually by an administrative user or if it crashed due to internal corruption.

---

### Section: Event ID 1000 & 1002 — Application Crashes & Hangs
- **Log Channel:** Application
- **Source:** Application Error (1000), Application Hang (1002)
- **Severity:** Error

#### Event ID 1000 Description
`Faulting application name: <app.exe>, version: <ver>, time stamp: <hex>, faulting module name: <dll>, version: <ver>, exception code: <code (e.g. 0xc0000005)>`
Indicates that an application process crashed due to an unhandled exception.

#### Common Exception Codes
- `0xC0000005`: Access Violation (attempt to read or write unmapped memory).
- `0xC00000FD`: Stack Overflow.
- `0xC0000017`: Out of Memory / Insufficient Quota.
- `0x80000003`: Hardcoded breakpoint hit.

#### Event ID 1002 Description
`The program <app.exe> version <ver> stopped interacting with Windows and was closed.`
Indicates that the application main UI thread entered a deadlock or infinite loop and stopped pumping Windows messages.

---

### Section: Event ID 4625 — An Account Failed to Log On
- **Log Channel:** Security
- **Source:** Microsoft Windows security auditing.
- **Severity:** Failure Audit

#### Description
Generated when a logon request fails. Vital for detecting password attacks, brute force attempts, and credential stuffing.

#### Key Forensic Fields
- `TargetUserName`: Account name attempted.
- `WorkstationName`: Source machine name.
- `Source Network Address`: IP address originating the attempt (e.g. 192.168.159.x from ToN_IoT testbed).
- `Failure Reason` / `Substatus Code`:
  - `0xC000006A`: Bad username or password.
  - `0xC000006E`: Unknown user name.
  - `0xC0000234`: User account locked out due to excessive failed attempts.

#### Triage Threshold
More than 10 Event ID 4625 records within 60 seconds from the same source IP strongly indicates a distributed or automated brute force password attack.

---

### Section: Event ID 4688 — A New Process Has Been Created
- **Log Channel:** Security
- **Source:** Microsoft Windows security auditing.
- **Severity:** Success Audit

#### Description
Generated when a new process is spawned. When process command-line auditing is enabled, it records the exact command string executed, providing direct insight into script executions (`powershell -enc ...`, `cmd.exe /c ...`).

#### Forensic Fields
- `Process Name`: Full path to the executable created.
- `Process CommandLine`: Complete arguments passed to the process.
- `Creator Process Name`: Parent process that spawned the child.
- `SubjectUserSid`: User account under whose context the process was created.

---

### Section: Event ID 1102 & 104 — The Audit Log Was Cleared
- **Log Channel:** Security (1102), System (104)
- **Source:** Microsoft Windows security auditing / Eventlog
- **Severity:** Information / High Alert

#### Description
`The audit log was cleared.`
Clearing Windows event logs is a definitive defense evasion technique (MITRE ATT&CK T1070). Legitimate administrators rarely clear event logs without archiving. Any instance should immediately elevate incident severity to `CRITICAL` and trigger host isolation.
