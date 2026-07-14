# NIST Incident Response Lifecycle

**Author:** Ritesh Gupta

A summary of the four NIST IR phases, with core activities and technologies for each.

---

## Phase 1: Preparation

Preparation means getting ready before any incident happens. It creates the foundation that determines how well an organization responds when a real threat appears.

During this phase, organizations put in place the policies, plans, teams, and tools that form the backbone of their response capability. How well prepared you are before a breach directly affects how successfully you'll manage incidents when they occur.

**Core Activities:**
- Develop an incident response plan and playbook
- Define roles and responsibilities
- Build and train your incident response team
- Implement detection and monitoring tools
- Establish communication protocols and escalation paths

**Common Technologies:**
- Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solutions
- Security Information and Event Management (SIEM) systems
- Network traffic analysis tools
- Log management and collection systems
- Intrusion detection and forensic tools

---

## Phase 2: Detection & Analysis

Detection and analysis focus on identifying, investigating, and confirming potential security incidents. This phase determines the nature and impact of a threat, including its severity, the systems affected, and the extent of the compromise.

**Detection Sources:**
- EDR/XDR agents: monitor endpoints for suspicious behavior
- SIEM and log management systems: aggregate logs and generate alerts based on predefined rules
- Network traffic monitoring, IDS/IPS: identify malicious patterns, signatures, or abnormal traffic
- Threat intelligence feeds: provide external insights into known attack campaigns
- User reports or external notifications: highlight unusual behavior or system disruptions

**Analysis: From Alert to Confirmation**

The analysis phase turns alerts into actionable insights through investigation and validation:
- Triage and initial filtering
- Classification and prioritization
- Event correlation
- Evidence collection
- Scope and vector determination

---

## Phase 3: Containment, Eradication & Recovery

This phase focuses on stopping the spread of an incident, removing the threat from affected environments, and restoring normal operations. Although NIST groups containment, eradication, and recovery into one phase, they involve distinct but interconnected actions that occur in parallel.

### Containment

Containment aims to limit further damage and protect business continuity while preparing for full remediation. The strategy depends on the type and severity of the incident. For example, a malware infection may require isolating systems, while a compromised account may call for disabling credentials and ending active sessions.

Containment typically involves two levels of action:
- Short-Term Containment
- Long-Term Containment

### Eradication

Once containment is achieved, the next step involves completely removing the attacker's presence and restoring system integrity. Eradication focuses on eliminating all traces of the threat, including malicious files, backdoors, and exploited vulnerabilities.

**Typical eradication activities:**
- Deleting malware, scripts, and unauthorized files
- Closing exploited access points
- Terminating compromised accounts and credentials
- Patching affected software and configurations
- Rebuilding or sanitizing compromised systems
- Running validation scans or forensic reviews to confirm full removal

### Recovery

Recovery focuses on restoring systems and services to full functionality while verifying that the environment is secure. The process should be gradual, beginning with the most critical systems.

**Common recovery steps:**
- Restoring clean data and system backups
- Rebuilding affected machines
- Reapplying patches and hardening configurations
- Resetting passwords and enforcing stronger authentication
- Monitoring for residual or recurring malicious activity

---

## Phase 4: Post-Incident Activity (Lessons Learned)

The post-incident activity phase focuses on turning every incident into an opportunity to strengthen defenses. It involves reviewing what happened, documenting lessons learned, and applying improvements that make future responses faster and more effective.

While often overlooked, this phase is critical for long-term resilience and continuous improvement.

**Key activities:**
- Conducting a lessons-learned review
- Creating a post-incident report
- Updating plans, playbooks, and controls
- Sharing knowledge and intelligence

Each post-incident review feeds improvements back into the preparation phase. Over time, this feedback loop builds stronger defenses, faster detection, and more coordinated response capabilities, making the organization more resilient with every cycle.
