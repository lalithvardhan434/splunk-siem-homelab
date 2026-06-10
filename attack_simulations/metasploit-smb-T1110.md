# Attack Walkthrough: SMB Brute Force (MITRE T1110)

## Overview
| Field | Detail |
|---|---|
| Technique | T1110 — Brute Force / T1110.001 — Password Guessing |
| Tactic | Credential Access (TA0006) |
| Tool | Metasploit Framework — auxiliary/scanner/smb/smb_login |
| Attacker | KALI_ATTACKER (Kali Linux — UTM on MacBook M2) |
| Target | WINDOWS_TARGET (Windows 10 VM — VirtualBox on Windows PC) |
| Detection | Windows Security Event ID 4625 + 4740 |
| Outcome | Detected — account lockout triggered |

## Objective

Simulate a credential brute force attack against the Windows SMB service (port 445) using the rockyou.txt wordlist, targeting the Administrator account — mapping to MITRE T1110.001 (Password Guessing).

## Why Metasploit Instead of Hydra

Hydra was attempted first but returned `invalid reply from target` due to modern Windows 10 SMB restrictions rejecting its authentication method. Metasploit smb_login handles SMBv2 natively and represents a more realistic adversary tool used in real-world credential attacks.

## Attack Commands

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS WINDOWS_TARGET
set SMBUser administrator
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 1
run
```

## Metasploit Output

```
[*] WINDOWS_TARGET:445 - Starting SMB login bruteforce
[-] WINDOWS_TARGET:445 - Failed: '.\administrator:123456'
[-] WINDOWS_TARGET:445 - Failed: '.\administrator:password'
[-] WINDOWS_TARGET:445 - Failed: '.\administrator:iloveyou'
[-] WINDOWS_TARGET:445 - Failed: '.\administrator:princess'
[!] WINDOWS_TARGET:445 - Account lockout detected on 'administrator'
[*] Bruteforce completed — 0 credentials successful
```

## Detection 1 — Failed Logins (Event ID 4625)

```spl
index=main source="WinEventLog:Security" EventCode=4625 earliest=-30m
| stats count by Account_Name
| sort -count
```

**Result:**
| Account_Name | count |
|---|---|
| administrator | 10 |

## Detection 2 — Account Lockout (Event ID 4740)

```spl
index=main source="WinEventLog:Security" EventCode=4740 earliest=-30m
| table _time, Account_Name, host
```

**Result:**
| _time | Account_Name | host |
|---|---|---|
| 2026-06-09 16:17:40 | Administrator | windows |

## Full Security Event Overview

```spl
index=main source="WinEventLog:Security" earliest=-30m
| stats count by EventCode
| sort -count
```

**Result:** 392 events across 13 EventCodes including:

| EventCode | Count | Description |
|---|---|---|
| 4907 | 274 | Auditing settings changed |
| 5379 | 53 | Credential Manager read |
| 4624 | 16 | Successful logon |
| 4625 | 10 | Failed logon — brute force evidence |
| 4740 | 1 | Account lockout |

## Analyst Notes

Multiple failed authentication attempts (Event ID 4625) against the Administrator account within a short timeframe is a strong indicator of a brute force attack. The high frequency of attempts against a single privileged account aligns with MITRE T1110.001 (Password Guessing).

The subsequent account lockout (Event ID 4740) at 16:17:40 confirms the attack generated sufficient failed attempts to trigger the Windows lockout policy. This provides a precise timestamp pivot point for incident timeline reconstruction.

**Key Observations:**
- Attack targeted the built-in Administrator account — highest privilege target
- Account lockout policy activated — demonstrates defensive control effectiveness
- No successful authentication — attack was contained
- Attack duration approximately 4 minutes

**Recommended Response:**
- Immediately isolate KALI_ATTACKER at network level
- Unlock Administrator account only after source is confirmed benign
- Review Event ID 4624 (successful logons) around the same timeframe
- Implement failed login alerting threshold of 5 attempts in 60 seconds
- Consider disabling built-in Administrator and using named admin accounts

## MITRE ATT&CK

| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | T1110 — Brute Force |
| Sub-technique | T1110.001 — Password Guessing |
| Platform | Windows |
| Data Sources | Windows Security Log, Sysmon |
| Mitigations | M1036 — Account Use Policies, M1032 — Multi-factor Authentication |
