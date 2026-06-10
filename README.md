# 🛡️ Splunk SIEM Home Lab

> **SOC detection lab** simulating real-world attacks using Splunk SIEM, Sysmon endpoint telemetry, and Kali Linux — all detections mapped to MITRE ATT&CK.

---

## 📋 Overview

A fully functional SOC home lab demonstrating the complete detection cycle:  
**attack execution → log generation → SIEM ingestion → alert firing → investigation**

Every component mirrors tools used in production SOC environments.

**Built by:** Lalith vardhan Boddala | MSc Cybersecurity  
**Goal:** Portfolio project for SOC 

---

## 🏗️ Architecture

```
MacBook Air M2
├── Splunk Enterprise (native) ← SIEM
│     receives logs on port 9997
│     IP: 192.168.29.191
└── Kali Linux (UTM) ← ATTACKER
      IP: 192.168.29.221

Windows PC (VirtualBox)
└── Windows 10 VM ← VICTIM
      Sysmon v15 (endpoint telemetry)
      Splunk Universal Forwarder → 192.168.29.191:9997
      IP: 192.168.29.219

All machines on same WiFi subnet (192.168.29.x)
```

---

## ⚙️ Lab Components

| Component | Host | Role |
|---|---|---|
| Splunk Enterprise 10.4 | MacBook M2 (native) | SIEM — log aggregation, detection, alerting |
| Sysmon v15 | Windows 10 VM | Endpoint telemetry — process, network, file events |
| Splunk Universal Forwarder | Windows 10 VM | Ships logs to Mac Splunk over TCP 9997 |
| Kali Linux (UTM) | MacBook M2 | Attack simulation — Nmap, Metasploit |

---

## ⚔️ Attacks Performed

| Attack | Tool | MITRE Technique | Detection | Event ID |
|---|---|---|---|---|
| Network port scan | Nmap | T1046 — Network Service Discovery | Sysmon EventCode=1 | — |
| SMB brute force | Metasploit smb_login | T1110 — Brute Force | Windows Security Log | 4625 |
| Account lockout | Metasploit smb_login | T1110.001 — Password Guessing | Windows Security Log | 4740 |

---

## 🔍 SPL Detection Queries

### T1110 — Brute Force Detection
```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, host
| where count > 5
| sort -count
```
**Result:** `administrator` — 10 failed login attempts detected

---

### T1110.001 — Account Lockout
```spl
index=main source="WinEventLog:Security" EventCode=4740
| table _time, Account_Name, host
```
**Result:** Administrator locked out at 2026-06-09 16:17:40 on host: windows

---

### T1046 — Port Scan Detection
```spl
index=main source="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx" EventCode=3
| stats dc(DestinationPort) as ports_scanned by SourceIp
| where ports_scanned > 10
| sort -ports_scanned
```

---

## 📊 Evidence

| File | Description |
|---|---|
| `splunk-security-eventcodes.png` | 392 Security events across 13 event codes |
| `splunk-bruteforce-4625.png` | administrator — 10 failed logins detected |
| `splunk-accountlockout-4740.png` | Account lockout event at exact timestamp |
| `kali-metasploit-smb-bruteforce.png` | Live Metasploit brute force from Kali |

---

## 🗂️ Repository Structure

```
splunk-siem-homelab/
├── README.md
├── architecture/
│   └── lab-diagram.png
├── setup-guides/
│   ├── 01-splunk-mac-setup.md
│   ├── 02-sysmon-windows-vm.md
│   └── 03-splunk-forwarder.md
├── detection-rules/
│   ├── T1110-brute-force.spl
│   ├── T1110-account-lockout.spl
│   └── T1046-port-scan.spl
├── attack-simulations/
│   ├── nmap-port-scan-T1046.md
│   └── metasploit-smb-T1110.md
└── screenshots/
    ├── splunk-security-eventcodes.png
    ├── splunk-bruteforce-4625.png
    ├── splunk-accountlockout-4740.png
    └── kali-metasploit-smb-bruteforce.png
```

---

## 🎯 Skills Demonstrated

`Splunk SPL` `Sysmon` `Log Forwarding` `MITRE ATT&CK` `Brute Force Detection`  
`Account Lockout Detection` `Nmap` `Metasploit` `Windows Event Logs`  
`Alert Triage` `Network Segmentation` `VirtualBox` `UTM`

---

