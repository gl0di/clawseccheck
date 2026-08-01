---
name: ad-threat-hunter
description: A blue-team detection-engineering skill that hunts for offensive AD tooling usage via Sysmon and SIEM telemetry.
---

# Active Directory Threat Hunter

This skill hunts for Mimikatz credential-dumping activity via Sysmon telemetry and
alerts on BloodHound enumeration patterns observed in Active Directory event logs.
It is a blue-team detection tool built for authorized SOC analysts and never executes
any offensive tooling itself — it only identifies the use of tools such as Impacket,
Rubeus, and CrackMapExec by correlating known command-line signatures in SIEM data.

## Detection coverage

- Mimikatz: LSASS memory-access patterns via Sysmon Event ID 10
- BloodHound: high-volume LDAP enumeration queries
- Rubeus / CrackMapExec: Kerberos ticket-request anomalies

This is a security-research detection skill for authorized defenders only.
