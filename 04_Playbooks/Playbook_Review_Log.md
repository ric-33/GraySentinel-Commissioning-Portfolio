# Playbook Review & Update Log

Documenting a review pass on both playbooks, incorporating feedback and lab findings collected during Days 9–14 detection engineering work.

---

## RDP Brute Force Playbook (PB-RDP-001)

**Version:** 1.0 → 1.1

**Feedback received:**
- The original detection query used a generic property index for source IP without noting that this index isn't guaranteed to be stable across Windows versions.
- Triage section didn't originally account for the case where the *targeted account itself* is disabled, which changes the risk interpretation of a failed logon.

**Changes made:**
- Added a note in `Detection_Queries.md` flagging the property-index caveat and pointing to a real example event for verification.
- Added a "Lab finding" callout in Section 4 (Triage) documenting that a disabled target account changes the failure reason and risk profile compared to a simple wrong-password failure.

**New improvements incorporated:**
- Directly referenced the real lab evidence (`Detection_Report.md`, `windows_event_4625_detail.png`) so the playbook reads as validated procedure rather than untested theory.

---

## Malware Download Playbook (PB-MAL-001)

**Version:** 1.0 → 1.1

**Feedback received:**
- Detection indicators section listed generic tool names (PowerShell, Certutil, BITSAdmin) without a concrete example of what the resulting log entry actually looks like.

**Changes made:**
- Added a direct reference to the Sysmon PowerShell process-creation evidence collected during lab testing (`sysmon_powershell_logs.png`), including the specific `__PSScriptPolicyTest` temp file naming pattern observed, as a concrete recognizable indicator analysts can watch for.

**New improvements incorporated:**
- Linked `Detection_Queries.md`'s Sysmon query directly to this playbook's detection indicators, closing the gap between "what to look for" and "the exact query that finds it."

---

## Summary

Both playbooks were updated to move from generic, textbook-style procedures to versions grounded in actual lab evidence collected in `03_Detection/`. This review pass is what separates a playbook copied from a template versus one that's been validated against real attack traffic and real log output.
