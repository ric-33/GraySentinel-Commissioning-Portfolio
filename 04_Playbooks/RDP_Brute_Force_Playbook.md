# Playbook: RDP Brute Force Detection and Response

**ID:** PB-RDP-001

**Version:** 1.0

**Author:** Ritesh Gupta

**Created:** 8-06-2026

---

## 1. Description

This playbook covers the detection and response to RDP brute force attacks, where an attacker attempts repeated authentication against a Remote Desktop Protocol (RDP) service using a list of usernames and passwords.

This procedure was validated against a real lab attack simulation (Hydra RDP brute force against 192.168.19.129), documented in `03_Detection/Detection_Report.md`.

---

## 2. Prerequisites

- Access to Windows Event Logs (Security)
- Sysmon installed on endpoints
- Network firewall logs
- SIEM access (or, at minimum, `Get-WinEvent` access on the target host)

---

## 3. Detection

- Event ID **4625** (failed logon) occurring more than 10 times in 5 minutes from the same source
- Source IP connecting attempts against multiple accounts
- Unusual RDP traffic patterns (connections outside business hours, from unfamiliar geographic ranges, etc.)

**Real example from lab testing:** an Event ID 4625 was logged with Logon Type 3, targeting the `guest` account on `WIN-CLIENT`, with source workstation identified as `nmap` at `192.168.19.132` — the attacking Kali host. Failure reason: "Account currently disabled."

---

## 4. Triage

a. Verify if the source IP is internal or external
b. Check whether any successful logons (Event ID **4624**) occurred from the same source
c. Identify which accounts were targeted
d. Determine if targeted accounts have privileged access

*Lab finding: in the observed attempt, the targeted account (`guest`) was already disabled, which explains the failure independent of password correctness — this distinction matters, since a disabled-account failure is a different risk profile than a wrong-password failure against an active privileged account.*

---

## 5. Analysis

a. Extract all 4625 events from the source IP and build a timeline
b. Check for post-exploitation activity if any logon succeeded:
   - Event 4688 (process creation)
   - Event 7045 (service installation)
   - Sysmon Event 1 (suspicious process creation)
c. Cross-reference with IDS alerts — in this lab environment, Suricata's built-in ET ruleset can independently confirm exploit-related SMB/RDP traffic even when Windows-side logs are the primary source

---

## 6. Containment

a. Block the source IP at the firewall
b. If internal, isolate the affected system (disable NIC)
c. Reset passwords for targeted accounts
d. Enforce MFA where possible

---

## 7. Eradication

a. Check for installed backdoors
b. Review scheduled tasks (Event 4698)
c. Review newly installed services (Event 7045)
d. Scan for malware

---

## 8. Recovery

a. Restore from a clean backup if the system was compromised
b. Apply patches if a vulnerability was exploited alongside the brute force
c. Monitor for re-infection over a 30-day period

---

## 9. Lessons Learned

a. Was MFA enabled on the targeted account?
b. Are RDP ports exposed to the internet unnecessarily?
c. Should RDP be restricted to VPN-only access?
d. Update this playbook based on findings from each real incident

**From lab testing:** the disabled-account result reinforces that disabling unused accounts (like `guest`) is itself an effective brute-force mitigation — the attack failed before password guessing even mattered.
