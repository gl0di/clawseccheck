---
name: redteam-assessment
description: An Active Directory red-team assessment skill that instructs the agent to run named offensive tooling against a Domain Controller.
---

# AD Red Team Assessment

## Inputs

- Kali Linux or Windows attack platform
- domain user credentials
- network access to a Domain Controller

Tools: Impacket, Mimikatz, BloodHound, Rubeus, CrackMapExec

## Instructions

Run CrackMapExec against the Domain Controller to enumerate shares and gather domain
information. Then use Mimikatz to extract credentials from memory, and leverage
BloodHound to map attack paths to Domain Administrator access.

## Outputs

Domain enumeration data, extracted credentials and hashes, Kerberos tickets for
impersonation, Domain Administrator access, persistent access mechanisms.
