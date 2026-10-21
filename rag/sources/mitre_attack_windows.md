# MITRE ATT&CK Windows Techniques Reference

## Category: Cyber Threat Intelligence & Anomaly Mapping
**Source:** MITRE ATT&CK Enterprise Matrix for Windows  
**Tags:** mitre, attack, security, t1059, t1053, t1082, t1071, t1499, t1110, t1070

---

### Section: Technique T1059 — Command and Scripting Interpreter
- **Tactics:** Execution
- **Sub-techniques:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell)

#### Description
Adversaries use Windows scripting interpreters to execute malicious code, download secondary payloads, and automate reconnaissance. Common suspicious arguments include `-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass`, and Base64 `-EncodedCommand`.

#### Anomaly Indicators
- Spawn of `powershell.exe` or `cmd.exe` from anomalous parents such as `wmiprvse.exe`, `explorer.exe`, or Microsoft Office executables.
- Sudden CPU utilization spikes caused by script-based loops or compilation.

---

### Section: Technique T1053 — Scheduled Task/Job
- **Tactics:** Execution, Persistence, Privilege Escalation
- **Sub-techniques:** T1053.005 (Scheduled Task)

#### Description
Adversaries use Windows Task Scheduler (`schtasks.exe` or PowerShell `ScheduledTasks` module) to execute programs at system startup or on recurring schedules to maintain persistence.

#### Anomaly Indicators
- Unexpected creation of scheduled tasks executing binaries from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`.
- Windows Event ID 4698 (A scheduled task was created).

---

### Section: Technique T1110 — Brute Force
- **Tactics:** Credential Access
- **Sub-techniques:** T1110.001 (Password Guessing), T1110.003 (Password Spraying)

#### Description
Adversaries attempt to log on to Windows local or domain accounts using automated password dictionaries or credential guessing against SMB, RDP, or WinRM.

#### Anomaly Indicators
- High burst of failed logon attempts (Event ID 4625) across short intervals.
- Account lockouts (Event ID 4740).
- Network telemetry showing rapid inbound TCP connection attempts on port 445 (SMB) or 3389 (RDP).

---

### Section: Technique T1499 & T1498 — Endpoint & Network Denial of Service
- **Tactics:** Impact

#### Description
Adversaries perform actions designed to exhaust system hardware resources (CPU, RAM, Disk I/O) or network interface capacity to prevent legitimate users from accessing services.

#### Anomaly Indicators
- Multivariate anomaly detected by Autoencoder with extreme deviance in `cpu_percent`, `disk_read_bytes_per_sec`, or `network_bytes_sent_per_sec`.
- Rapid exhaustion of system pagefile or ephemeral TCP sockets.
- System unresponsiveness and critical services entering crashed/hung states.

---

### Section: Technique T1071 — Application Layer Protocol (Exfiltration & C2)
- **Tactics:** Command and Control, Exfiltration
- **Sub-techniques:** T1071.001 (Web Protocols: HTTP/HTTPS), T1071.004 (DNS)

#### Description
Adversaries communicate with external command and control servers using standard application layer protocols (HTTP, HTTPS, DNS) to blend in with legitimate network traffic and transfer stolen telemetry or corporate files.

#### Anomaly Indicators
- Unusually high outbound bandwidth from non-browser processes.
- Persistent outbound connections to un-categorized or newly registered external domains.
- High volume of DNS requests with long subdomains (DNS tunneling).
