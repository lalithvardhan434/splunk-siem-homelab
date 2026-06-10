# Attack Walkthrough: Nmap Port Scan (MITRE T1046)

## Overview
| Field | Detail |
|---|---|
| Technique | T1046 — Network Service Discovery |
| Tactic | Discovery (TA0007) |
| Tool | Nmap 7.98 |
| Attacker | KALI_ATTACKER (Kali Linux — UTM on MacBook M2) |
| Target | WINDOWS_TARGET (Windows 10 VM — VirtualBox on Windows PC) |
| Detection | Sysmon EventCode=1 (Process Create) |
| Outcome | Detected |

## Objective
Simulate adversary reconnaissance by scanning the target for open ports, running services, and OS fingerprint — mapping to MITRE T1046 (Network Service Discovery).

## Attack Command
```bash
nmap -sV -sC -O -p- WINDOWS_TARGET
```

Flags used:
- `-sV` — service version detection
- `-sC` — default NSE scripts
- `-O` — OS fingerprinting
- `-p-` — all 65,535 ports

## Nmap Results
| Port | State | Service | Version |
|---|---|---|---|
| 135/tcp | open | msrpc | Microsoft Windows RPC |
| 139/tcp | open | netbios-ssn | Microsoft Windows netbios-ssn |
| 445/tcp | open | microsoft-ds | SMB — Windows 10/11 |
| 7680/tcp | open | pando-pub | Unknown |
| 49668/tcp | open | msrpc | Microsoft Windows RPC |

**OS Detection:** Microsoft Windows 10/11 (97% confidence)  
**SMB Signing:** enabled but not required  
**NetBIOS name:** WINDOWS

## Detection in Splunk

```spl
index=main source="C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
  earliest=-30m "KALI_ATTACKER"
| head 20
```

**Result:** Sysmon EventCode=1 (Process Create) captured:
- Image: `C:\Windows\System32\PING.EXE`
- CommandLine: `ping KALI_ATTACKER`
- User: `WINDOWS\vboxuser`
- ParentImage: `C:\Windows\System32\cmd.exe`

## Analyst Notes

The Nmap scan triggered Sysmon EventCode=1 recording PING.EXE execution with the attacker IP as the destination. This confirms Sysmon is capturing all network reconnaissance initiated toward or from the endpoint.

The open SMB port (445) identified during this scan directly enabled the subsequent brute force attack. In a real SOC investigation, this scan would be flagged as the precursor activity — the attacker performing target enumeration before credential attacks.

**Recommended Response:**
- Block source IP at perimeter firewall
- Review all subsequent connections from the scanning host
- Check for successful authentication attempts following the scan

## MITRE ATT&CK

| Field | Value |
|---|---|
| Tactic | Discovery (TA0007) |
| Technique | T1046 — Network Service Discovery |
| Platform | Windows |
| Data Source | Sysmon EventCode=1, Windows Event Logs |
