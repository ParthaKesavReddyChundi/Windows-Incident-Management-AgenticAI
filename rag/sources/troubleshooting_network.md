# Windows Network Anomaly Troubleshooting Guide

## Category: Network Saturation, Socket Exhaustion & Malicious Traffic
**Source:** Windows Systems Administration & Cybersecurity Runbooks  
**Tags:** network, saturation, ddos, socket_exhaustion, exfiltration, firewall, syn_flood, mitm

---

### Section: Network Saturation Overview
Network anomaly incidents occur when network interface bandwidth is saturated by inbound flood attacks (DDoS/DoS) or outbound data transmission surges (data exfiltration, peer-to-peer distribution), leading to packet loss, dropped connections, and communication timeouts.

#### Common Symptoms
- Network interface utilization reaches maximum link capacity (e.g. 1 Gbps or 100 Mbps).
- High rate of packet retransmissions and dropped packets (`dropin`, `dropout`).
- Remote desktop (RDP), SSH, or web applications experience severe latency or disconnect.
- TCP ephemeral port pool exhausted; new outbound connections fail with `WSAENOBUFS` (10055).

#### Key Performance Metrics
- `bytes_sent_per_sec`: Outbound transmission rate in bytes per second.
- `bytes_recv_per_sec`: Inbound reception rate in bytes per second.
- `packets_sent_per_sec` / `packets_recv_per_sec`: Packet transfer rates.
- `TCP: Connections Established`: Active open TCP connections.
- `TCP: Connection Failures`: Rate at which connection requests have failed.

---

### Section: Abnormal Outbound Burst & Data Exfiltration
A sudden massive surge in outbound network traffic (`bytes_sent_per_sec` exceeding 50 MB/s or hundreds of thousands of packets) originating from an internal host to external destinations.

#### Root Causes
- Data exfiltration by an adversary or malware uploading enterprise files or database dumps to a cloud staging server or C2 server.
- The host has been compromised and enlisted as a bot in a distributed denial-of-service (DDoS) botnet executing outbound UDP/SYN floods.
- Misconfigured automated backup or file synchronization script transmitting large uncompressed archives during peak hours.

#### Diagnostic Procedure
1. Inspect `network_collector` telemetry for asymmetric traffic patterns: `bytes_sent` >> `bytes_recv`.
2. Inspect active TCP/UDP connections and determine which local PID owns the traffic:
   `Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess`.
3. Resolve the remote IP address and check threat intelligence reputation.
4. Cross-reference `OwningProcess` PID with `process_collector` to determine the executable path.

#### Remediation Actions
1. **Host Network Isolation (High Risk / Immediate Containment):** If malicious exfiltration is confirmed, isolate the host from the network while preserving local telemetry:
   `New-NetFirewallRule -DisplayName "Emergency Quarantine" -Direction Outbound -Action Block -Profile Any`.
2. **Terminate Offending Process (Medium Risk):** Terminate the process driving the high-volume outbound network socket: `Stop-Process -Id <PID> -Force`.
3. **Block Remote Malicious IP (Low Risk):** Add a targeted firewall block rule:
   `New-NetFirewallRule -DisplayName "Block C2 IP" -Direction Outbound -RemoteAddress <Remote_IP> -Action Block`.
4. **Flush DNS Cache & Reset Netsh (Low Risk):** Reset Windows networking stack and flush cached resolvers: `Clear-DnsClientCache; netsh int ip reset`.

---

### Section: Inbound Denial of Service (DoS / DDoS)
An overwhelming volume of incoming connection requests or traffic targeting host network interfaces.

#### Root Causes
- SYN flood exhausting TCP half-open connection backlog (`SYN_RECEIVED` state).
- HTTP/HTTPS flood exhausting web server worker pools.
- Volumetric UDP reflection attack saturating the network interface card (NIC).

#### Remediation Actions
1. Enable Windows TCP SYN Attack Protection (SynAttackProtect) in the Windows Registry:
   `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SynAttackProtect" -Value 2`.
2. Reduce TCP keep-alive time and half-open timeout to aggressively drop dead connections.
3. Apply Windows Filtering Platform (WFP) or Windows Defender Firewall rate-limiting rules.
