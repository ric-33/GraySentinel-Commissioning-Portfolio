# GraySentinel Commissioning Portfolio

## Overview
This portfolio documents my 45-day journey through the GraySentinel Cybersecurity Commissioning Program — progressing from Recruit (Day 1) through Commissioned Operator (Day 45), covering reconnaissance, exploitation, detection engineering, threat hunting, and incident response.

**Program:** GraySentinel Commissioning (Days 1–45)  

**Completion Date:** 14 July 2026 

**Author:** Ritesh Gupta

---

## About Me

**Cybersecurity Professional** with hands-on expertise in:
- **Blue Team (SOC):** Threat hunting, detection engineering, incident response, log analysis
- **Red Team:** Network reconnaissance, exploitation techniques, privilege escalation, lateral movement
- **Security Engineering:** Custom detection rules, automation scripts, security tool configuration

**Target Roles:** SOC Analyst | Threat Hunter | Security Engineer | Detection Engineer

---

## Portfolio Structure

### 📡 [01_Reconnaissance](01_Reconnaissance/)
**Days 1–3:** Network mapping, OSINT, passive/active information gathering

- **[Recon_Report.md](01_Reconnaissance/Recon_Report.md)** — Comprehensive reconnaissance findings
  - Passive DNS reconnaissance, active network scanning with Nmap
  - SMB/RDP enumeration against Windows targets
  - Service identification and vulnerability surface mapping
  - OSINT tool demonstrations (theHarvester, Dig, Shodan simulation)

**Key Findings:** Identified open ports (445 SMB, 3389 RDP, 139 NetBIOS), enumerated shares, discovered firewall evasion signatures

---

### ⚔️ [02_Exploitation](02_Exploitation/)
**Days 4–8:** Hands-on exploitation techniques, post-exploitation, credential dumping

- **[Exploitation_Report.md](02_Exploitation/Exploitation_Report.md)** — Full exploitation chain documentation
  - MS17-010 (EternalBlue) vulnerability verification and exploitation via Metasploit
  - Meterpreter post-exploitation: process enumeration, credential dumping (hashdump)
  - Password hash cracking (John the Ripper for NTLM and Linux shadow hashes)
  - RDP/SSH brute force attacks with Hydra
  - Custom payload generation with MSFVenom
  - Custom wordlist creation from DVWA target (CeWL)

**Key Achievements:** SYSTEM-level RCE achieved, Administrator credentials extracted, lateral movement vectors identified

---

### 🛡️ [03_Detection](03_Detection/)
**Days 9–12:** IDS/IPS configuration, detection rule writing, endpoint logging

- **[Detection_Report.md](03_Detection/Detection_Report.md)** — Detection engineering validation
  - Suricata IDS installation and configuration (8.0.5)
  - Custom detection rules for ICMP, SMB, HTTP brute force
  - Built-in ET ruleset validation (EternalBlue signature test)
  - Sysmon deployment and PowerShell event logging
  - Windows Event Log correlation (Event ID 4625 for failed logons)
  - Attack-to-alert correlation workflow

**Key Achievements:** Successfully detected EternalBlue exploitation attempt even when exploit failed; correlated RDP brute force with Windows security events

---

### 📋 [04_Playbooks](04_Playbooks/)
**Days 14–15:** Incident response documentation and automation

- **[IR_Lifecycle_Summary.md](04_Playbooks/IR_Lifecycle_Summary.md)** — NIST 4-phase incident response framework
- **[RDP_Brute_Force_Playbook.md](04_Playbooks/RDP_Brute_Force_Playbook.md)** — PB-RDP-001 (Triage → Eradication → Recovery)
- **[Malware_Download_Playbook.md](04_Playbooks/Malware_Download_Playbook.md)** — PB-MAL-001 (PowerShell cradle detection & response)
- **[Detection_Queries.md](04_Playbooks/Detection_Queries.md)** — PowerShell queries for RDP brute force and malware download detection
- **[Playbook_Review_Log.md](04_Playbooks/Playbook_Review_Log.md)** — Version history and improvements from lab evidence

**Key Achievements:** Integrated real lab findings into playbook procedures; demonstrated evidence-based documentation

---

### 🔧 [05_Scripts](05_Scripts/)
**Days 16–19:** Security automation and log analysis tooling

Reusable scripts for reconnaissance, log analysis, and endpoint monitoring:

- **[lab_setup.sh](05_Scripts/lab_setup.sh)** — Automated lab environment initialization
- **[log_analyzer.sh](05_Scripts/log_analyzer.sh)** — Bash log parser for authentication analysis
- **[network_mapper.sh](05_Scripts/network_mapper.sh)** — Network discovery and Nmap wrapper
- **[nmap_automator.sh](05_Scripts/nmap_automator.sh)** — Automated Nmap scanning with output formatting
- **[advanced_log_analyzer.sh](05_Scripts/advanced_log_analyzer.sh)** — Multi-log analyzer (auth + web access logs)
- **[event_collector.ps1](05_Scripts/event_collector.ps1)** — Windows Event Log collection and export
- **[sysmon_collector.ps1](05_Scripts/sysmon_collector.ps1)** — Sysmon event harvesting with PowerShell filtering

**Use Cases:** Lab automation, log triage, endpoint data collection, incident response tooling

---

### 📊 [06_Reports](06_Reports/)
**Days 13, 17, 22:** Professional security assessments and threat analysis

- **[Vulnerability_Assessment_Report.md](06_Reports/Vulnerability_Assessment_Report.md)** (Task 17.5)
  - OpenVAS/GVM vulnerability scanner configuration and scan results
  - Nmap NSE vulnerability script findings (MS17-010, MS10-061)
  - Authenticated vs. unauthenticated scanning comparison
  - Vulnerability prioritization matrix (CVSS scoring)
  - Remediation recommendations (immediate, short-term, long-term)

- **[Lateral_Movement_Report.md](06_Reports/Lateral_Movement_Report.md)** (Task 22.5)
  - PSExec exploitation with plaintext credentials (successful RCE)
  - Pass-the-Hash (PTH) lateral movement technique (hash-only authentication)
  - Attack-to-defense implications and detection opportunities
  - Credential hygiene and network segmentation recommendations

- **[Threat_Intelligence_Report.md](06_Reports/Threat_Intelligence_Report.md)** (Task 13.4)
  - Threat landscape assessment and active threat group analysis
  - MITRE ATT&CK technique mapping to observed lab attacks
  - Indicators of Compromise (IoCs) from exploitation & lateral movement
  - Alert-to-feed correlation workflow
  - Threat feed sources and vulnerability intelligence summary

**Key Achievements:** Grounded reports in real lab evidence; integrated detections with threat intel; provided actionable recommendations

---

### 🔍 [07_Hunting](07_Hunting/)
**Days 29–30:** Threat hunting methodology and multi-stage attack analysis

- **[Hunting_Hypothesis.md](07_Hunting/Hunting_Hypothesis.md)** (Task 29.2)
  - Formal hypothesis: "Can we detect PowerShell from unusual parents with network activity + temp file creation?"
  - Validation criteria and data collection strategy
  - Scope and methodology definition

- **[Hunting_Queries.md](07_Hunting/Hunting_Queries.md)** (Task 30.2)
  - PowerShell spawned from unusual parents (Event ID 1)
  - PowerShell + network connection correlation (Event ID 3)
  - File creation in %TEMP% detection (Event ID 11)
  - Process ancestry chain building
  - Registry modification hunting
  - KQL equivalents for Azure Sentinel / Log Analytics

- **[Process_Ancestry_Tree.md](07_Hunting/Process_Ancestry_Tree.md)** (Task 30.3)
  - Real process hierarchy: explorer.exe → powershell.exe → network + file creation
  - Malicious activity indicators and timing correlation
  - MITRE ATT&CK mapping to observed behaviors
  - Forensic indicator summary

- **[Attack_Timeline.md](07_Hunting/Attack_Timeline.md)** (Task 30.4)
  - Chronological attack chain reconstruction
  - Five phases: Initial Compromise → C2 Callback → Staging → Execution → Lateral Movement
  - Kill chain analysis using MITRE ATT&CK framework
  - Timeline gaps and investigative questions
  - Recommended detection rules derived from hunt

- **[Hunting_Investigation_Report.md](07_Hunting/Hunting_Investigation_Report.md)** (Task 30.5)
  - Investigation findings summary (Critical threat confirmed)
  - Hypothesis validation and evidence analysis
  - False positive assessment (5% chance, highly confident)
  - Impact assessment and recommendations
  - Detection rule generation from investigation

**Key Achievements:** Discovered real attack pattern in Sysmon logs; validated hypothesis with 95%+ confidence; generated actionable detection rules

---

## Skills Demonstrated

### Offensive Security
- **Reconnaissance:** Network mapping (Nmap), OSINT (theHarvester, Dig), passive information gathering
- **Exploitation:** Metasploit framework, EternalBlue (MS17-010), post-exploitation techniques
- **Credential Access:** Hash dumping (Meterpreter hashdump), password cracking (John, Hydra), privilege escalation
- **Lateral Movement:** Pass-the-Hash (PSExec), SMB exploitation, credential reuse analysis

### Defensive Security
- **Detection Engineering:** Custom Suricata rules, Sysmon configuration, detection validation
- **Threat Hunting:** Hypothesis-driven hunting, multi-stage attack analysis, process ancestry trees
- **Incident Response:** Playbook development, triage procedures, evidence preservation
- **Log Analysis:** Windows Event Logs (Security, PowerShell), Sysmon events, correlation workflows

### Tools & Technologies
- **Offensive:** Nmap, Metasploit, Hydra, John the Ripper, Mimikatz (concepts), CeWL, MSFVenom
- **Defensive:** Suricata, Sysmon, Windows Event Viewer, Get-WinEvent (PowerShell), Sigma rules (concepts)
- **Scripting:** Bash, PowerShell, Python fundamentals
- **Analysis:** Wireshark (packet analysis), process ancestry tracing, timeline reconstruction

---

## Key Findings & Lessons

### What Worked
- **Sysmon logging is critical** — Event IDs 1/3/11 provided visibility that Windows Event Logs alone couldn't
- **Behavior-based detection beats signatures** — All attack components were legitimate Windows tools used maliciously
- **Hypothesis-driven hunting finds threats** — Formal hunting methodology discovered real attack chain in 1-week lab data
- **Evidence-based documentation** — Grounding playbooks and reports in real lab findings creates credibility

### What Attackers Exploited
- **Unpatched systems** — Windows 7 without MS17-010 patch = instant RCE
- **Weak credentials** — Password123 led to entire attack chain; credential reuse across systems enabled PTH
- **Exposed admin services** — SMB/RDP accessible network-wide with no segmentation or NLA
- **Living-off-the-Land tactics** — PowerShell + explorer.exe + network + temp file evaded basic detection

### Defense Priorities
1. **Patch first** — MS17-010, MS10-061 patches are non-negotiable
2. **Segment the network** — Admin systems isolated from user segments
3. **Credential hygiene** — Unique local admin passwords (LAPS), strong policies, MFA
4. **Deploy Sysmon+EDR** — Endpoint visibility catches what network logs miss

---

## GraySentinel Program Context

This portfolio represents completion of the **GraySentinel 45-Day Commissioning Program**, structured as:

| Days | Phase | Focus |
|---|---|---|
| 1–10 | Recruit | Fundamentals, reconnaissance, basic exploitation |
| 11–20 | Operator | Detection, scripting, advanced exploitation |
| 21–30 | Specialist | Threat hunting, lateral movement, incident response |
| 31–45 | Commissioned Operator | Integration, advanced reporting, operational mastery |

**Progression:** Recruit → Operator (Day 10) → Specialist (Day 20) → **Commissioned Operator (Day 45)** ✅

---

## How to Use This Portfolio

### For Employers/Hiring Managers
1. Start with **01_Reconnaissance** or **02_Exploitation** to see offensive capabilities
2. Review **03_Detection** and **04_Playbooks** for defensive/SOC skills
3. Check **07_Hunting** for analytical and investigative depth

### For Learning/Reference
1. **Threat Hunters:** Use 07_Hunting queries and methodology as templates
2. **SOC Analysts:** Adapt playbooks (04_) and detection rules (03_) for your environment
3. **Penetration Testers:** Reference 01_Reconnaissance and 02_Exploitation for enumeration/exploitation workflows
4. **Security Engineers:** Use 05_Scripts as starting points for log analysis and automation

---

## Contact & Links

- **GitHub:** https://github.com/ric-33/GraySentinel-Commissioning-Portfolio
- **LinkedIn:** https://www.linkedin.com/in/ritesh-gupta-107834384/
- **Email:** ritesh11703@gmail.com

---

## Acknowledgments

This portfolio was completed as part of the **GraySentinel Commissioning Program** by Ritik Shrivas. The program provided structured guidance, lab environments, and real-world scenarios that enabled hands-on learning across offensive and defensive security domains.

---

## Notes & Disclaimers

- **Lab Environment:** All exploitation, lateral movement, and attack simulations were conducted in a controlled, authorized lab environment (192.168.x.x networks)
- **Educational Purpose:** This portfolio is for educational and portfolio demonstration purposes only
- **Ethical Use:** All techniques documented here should only be used in authorized penetration tests or in isolated lab environments with proper authorization

---

**Portfolio Status:** ✅ **Complete** (45 days, 7 folders, 30+ deliverables)  
**Last Updated:** 14 July 2026
