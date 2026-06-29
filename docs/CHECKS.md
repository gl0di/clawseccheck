# Check Catalog Reference

Generated from [clawseccheck/catalog.py](../clawseccheck/catalog.py) and [clawseccheck/risk.py](../clawseccheck/risk.py).

Regenerate with `python3 scripts/gen_checks_docs.py --write`.

## Verdict semantics

- PASS: no positive evidence for the issue
- FAIL: positive evidence for the issue
- WARN: partial or likely-insecure default; counts half-weight in the score
- UNKNOWN: cannot be determined from the available evidence; excluded from the score

Advisory checks are recorded for coverage but are not scored.

## Trifecta

### A1 - Lethal Trifecta (untrusted input × sensitive data × outbound)

- Severity: CRITICAL
- Block: trifecta
- Framework: Lethal Trifecta
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection, LLM06 Excessive Agency
- What it checks: Lethal Trifecta (untrusted input × sensitive data × outbound)
- Remediation:
  - none

## Hardening checks

### B1 - Secrets in plaintext config / bootstrap files

- Severity: CRITICAL
- Block: hardening
- Framework: Secrets Vault
- Scored: yes
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure
- What it checks: Secrets in plaintext config / bootstrap files
- Remediation:
  - command: `openclaw secrets configure`
  - command: `chmod 600 ~/.openclaw/openclaw.json`
  - command: `chmod 700 ~/.openclaw`

### B2 - Gateway exposure & channel authentication

- Severity: CRITICAL
- Block: hardening
- Framework: Zero Trust / Gateway
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection
- What it checks: Gateway exposure & channel authentication
- Remediation:
  - config: `gateway.auth` - enable gateway auth and restrict channels to an allowlist

### B3 - Least privilege (elevated tools / allowlists)

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Least privilege (elevated tools / allowlists)
- Remediation:
  - config: `tools.elevated.allowFrom` - restrict to an explicit allowlist (no wildcards)

### B4 - Execution sandbox

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege / Sandbox
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Execution sandbox
- Remediation:
  - config: `agents.defaults.sandbox.mode` = `"non-main"` - run exec tools in a sandbox

### B5 - Plugin / skill supply-chain integrity

- Severity: HIGH
- Block: hardening
- Framework: Supply Chain
- Scored: yes
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: Plugin / skill supply-chain integrity
- Remediation:
  - none

### B6 - Bootstrap-file injection surface (SOUL.md/AGENTS.md/TOOLS.md)

- Severity: HIGH
- Block: hardening
- Framework: Untrusted↔Trusted separation
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection
- What it checks: Bootstrap-file injection surface (SOUL.md/AGENTS.md/TOOLS.md)
- Remediation:
  - none

### B7 - Memory poisoning surface (MEMORY.md / memory dir)

- Severity: HIGH
- Block: hardening
- Framework: Memory integrity
- Scored: yes
- Confidence: HIGH
- OWASP: LLM04 Data and Model Poisoning
- What it checks: Memory poisoning surface (MEMORY.md / memory dir)
- Remediation:
  - none

### B8 - Human approval on destructive actions

- Severity: HIGH
- Block: hardening
- Framework: Human Approval
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Human approval on destructive actions
- Remediation:
  - config: `tools.exec.mode` = `"ask"` - require human approval before exec

### B9 - System-prompt / secret leak in tool output

- Severity: MEDIUM
- Block: hardening
- Framework: Egress / Leak
- Scored: yes
- Confidence: HIGH
- OWASP: LLM07 System Prompt Leakage, LLM02 Sensitive Information Disclosure
- What it checks: System-prompt / secret leak in tool output
- Remediation:
  - none

### B10 - Audit log & sensitive redaction

- Severity: MEDIUM
- Block: hardening
- Framework: Audit Log
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Audit log & sensitive redaction
- Remediation:
  - none

### B11 - Transport TLS & at-rest protection

- Severity: MEDIUM
- Block: hardening
- Framework: TLS & Encryption
- Scored: yes
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure
- What it checks: Transport TLS & at-rest protection
- Remediation:
  - none

### B12 - Local-first & model hygiene

- Severity: LOW
- Block: hardening
- Framework: Local First
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Local-first & model hygiene
- Remediation:
  - none

### B13 - Installed skill / plugin safety (downloaded, not self-made)

- Severity: HIGH
- Block: hardening
- Framework: Supply Chain / ClawHavoc
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM03 Supply Chain
- What it checks: Installed skill / plugin safety (downloaded, not self-made)
- Remediation:
  - none

### B14 - Egress surface (where the agent can reach out)

- Severity: MEDIUM
- Block: hardening
- Framework: Egress Control
- Scored: no
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure
- What it checks: Egress surface (where the agent can reach out)
- Remediation:
  - none

### B15 - MCP server trust boundaries

- Severity: HIGH
- Block: hardening
- Framework: MCP Trust
- Scored: yes
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: MCP server trust boundaries
- Remediation:
  - none

### B16 - Threat monitoring / detection in place

- Severity: MEDIUM
- Block: hardening
- Framework: Monitoring
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Threat monitoring / detection in place
- Remediation:
  - none

### B17 - Autonomy / heartbeat actions

- Severity: MEDIUM
- Block: hardening
- Framework: Autonomy Control
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency, LLM10 Unbounded Consumption
- What it checks: Autonomy / heartbeat actions
- Remediation:
  - none

### B18 - Subagent delegation

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Subagents
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Subagent delegation
- Remediation:
  - none

### B19 - Data at-rest protection (memory/logs)

- Severity: MEDIUM
- Block: hardening
- Framework: Data Protection
- Scored: yes
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure
- What it checks: Data at-rest protection (memory/logs)
- Remediation:
  - command: `chmod 700 ~/.openclaw`

### B20 - Bootstrap / memory write protection

- Severity: MEDIUM
- Block: hardening
- Framework: Write Integrity
- Scored: yes
- Confidence: HIGH
- OWASP: LLM04 Data and Model Poisoning
- What it checks: Bootstrap / memory write protection
- Remediation:
  - command: `chmod 700 <workspace>`
  - command: `chmod 600 <workspace>/SOUL.md <workspace>/AGENTS.md <workspace>/TOOLS.md <workspace>/MEMORY.md`

### B21 - Tool-output / retrieved-content trust boundary

- Severity: MEDIUM
- Block: hardening
- Framework: Prompt Injection / Trust Boundary
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection, LLM05 Improper Output Handling
- What it checks: Tool-output / retrieved-content trust boundary
- Remediation:
  - none

### B22 - Self-modification risk (identity/skill files writable + tools enabled)

- Severity: HIGH
- Block: hardening
- Framework: Write Integrity / Self-Modification
- Scored: yes
- Confidence: HIGH
- OWASP: LLM04 Data and Model Poisoning, LLM06 Excessive Agency
- What it checks: Self-modification risk (identity/skill files writable + tools enabled)
- Remediation:
  - command: `chmod 600 <workspace>/SOUL.md`
  - command: `chmod 700 <workspace>/skills`

### B23 - Approval-bypass directives in bootstrap

- Severity: HIGH
- Block: hardening
- Framework: Human Approval
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection, LLM06 Excessive Agency
- What it checks: Approval-bypass directives in bootstrap
- Remediation:
  - config: `tools.exec.mode` = `"ask"` - enforce the approval gate; do not let bootstrap text weaken it

### B24 - MCP server hardening

- Severity: HIGH
- Block: hardening
- Framework: MCP Trust
- Scored: yes
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: MCP server hardening
- Remediation:
  - none

### B25 - Update / pinning hygiene

- Severity: MEDIUM
- Block: hardening
- Framework: Supply Chain
- Scored: yes
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: Update / pinning hygiene
- Remediation:
  - none

### B30 - Sender identity strength (name-matching / mutable-ID bypass)

- Severity: MEDIUM
- Block: hardening
- Framework: Sender Identity
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection
- What it checks: Sender identity strength (name-matching / mutable-ID bypass)
- Remediation:
  - config: `channels.<provider>.dangerouslyAllowNameMatching` - remove this flag — a mutable display-name allowlist is trivially bypassed

### B31 - Effective-tools bypass (illusory deny — write blocked but apply_patch/exec still write)

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Tool Policy
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Effective-tools bypass (illusory deny — write blocked but apply_patch/exec still write)
- Remediation:
  - none

### B32 - Control-plane mutation reachability via gateway

- Severity: HIGH
- Block: hardening
- Framework: Control Plane
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Control-plane mutation reachability via gateway
- Remediation:
  - none

### B38 - Browser control / cookie & SSRF exposure

- Severity: HIGH
- Block: hardening
- Framework: Browser / SSRF
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Browser control / cookie & SSRF exposure
- Remediation:
  - config: `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` = `false` - block private-network requests from the browser tool

### B39 - Session visibility / cross-user transcript leak

- Severity: MEDIUM
- Block: hardening
- Framework: Session Isolation
- Scored: yes
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure
- What it checks: Session visibility / cross-user transcript leak
- Remediation:
  - config: `session.dmScope` - isolate DM sessions per user; do not use "main"

### B26 - Untrusted-context exposure (channels.contextVisibility)

- Severity: MEDIUM
- Block: hardening
- Framework: Injection Surface
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection
- What it checks: Untrusted-context exposure (channels.contextVisibility)
- Remediation:
  - none

### B33 - Known-vulnerable OpenClaw version gate

- Severity: HIGH
- Block: hardening
- Framework: Patch hygiene
- Scored: yes
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: Known-vulnerable OpenClaw version gate
- Remediation:
  - none

## Advisory checks

### B41 - Credential blast-radius assessment

- Severity: MEDIUM
- Block: advisory
- Framework: Credential / Blast Radius
- Scored: yes
- Confidence: HIGH
- OWASP: LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency
- What it checks: Credential blast-radius assessment
- Remediation:
  - none

## Hardening checks

### B42 - Skill/plugin install-time policy (postinstall hooks, writable skill dirs)

- Severity: MEDIUM
- Block: hardening
- Framework: Supply Chain / Install Policy
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM03 Supply Chain
- What it checks: Skill/plugin install-time policy (postinstall hooks, writable skill dirs)
- Remediation:
  - none

## Advisory checks

### B43 - Capability blast-radius / dangerous-verb inventory

- Severity: HIGH
- Block: advisory
- Framework: Least Privilege / Blast Radius
- Scored: no
- Confidence: ATTESTED
- OWASP: LLM06 Excessive Agency
- What it checks: Capability blast-radius / dangerous-verb inventory
- Remediation:
  - none

### B44 - Attestation ⇄ config mismatch (undisclosed capability)

- Severity: MEDIUM
- Block: advisory
- Framework: Trust Boundary / Drift
- Scored: no
- Confidence: ATTESTED
- OWASP: LLM06 Excessive Agency
- What it checks: Attestation ⇄ config mismatch (undisclosed capability)
- Remediation:
  - none

### B45 - Per-agent privilege separation (trifecta decomposition)

- Severity: HIGH
- Block: advisory
- Framework: Privilege Separation / Lethal Trifecta
- Scored: no
- Confidence: ATTESTED
- OWASP: LLM06 Excessive Agency
- What it checks: Per-agent privilege separation (trifecta decomposition)
- Remediation:
  - none

## Hardening checks

### B46 - Multi-agent trifecta exposure

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Agents
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: Multi-agent trifecta exposure
- Remediation:
  - none

## Advisory checks

### B47 - Cross-agent trifecta reassembly (delegation graph)

- Severity: HIGH
- Block: advisory
- Framework: Privilege Separation / Delegation
- Scored: no
- Confidence: ATTESTED
- OWASP: LLM05 Improper Output Handling, LLM06 Excessive Agency
- What it checks: Cross-agent trifecta reassembly (delegation graph)
- Remediation:
  - none

## Hardening checks

### B48 - Dangerous break-glass overrides enabled

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege / Break-Glass
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection, LLM06 Excessive Agency
- What it checks: Dangerous break-glass overrides enabled
- Remediation:
  - none

### B50 - Host network monitoring / IDS

- Severity: LOW
- Block: hardening
- Framework: Host Watch / Network IDS
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Host network monitoring / IDS
- Remediation:
  - none

### B51 - Host audit / syscall logging

- Severity: LOW
- Block: hardening
- Framework: Host Watch / Audit
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Host audit / syscall logging
- Remediation:
  - none

### B52 - Host file-integrity monitoring

- Severity: LOW
- Block: hardening
- Framework: Host Watch / FIM
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Host file-integrity monitoring
- Remediation:
  - none

### B53 - Host endpoint protection / EDR

- Severity: LOW
- Block: hardening
- Framework: Host Watch / EDR
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Host endpoint protection / EDR
- Remediation:
  - none

### B54 - Host firewall active

- Severity: LOW
- Block: hardening
- Framework: Host Watch / Firewall
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Host firewall active
- Remediation:
  - none

### B55 - Filesystem-write tool exposure (broad fs-write without scoping)

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege / Filesystem Write
- Scored: no
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency, LLM04 Data and Model Poisoning
- What it checks: Filesystem-write tool exposure (broad fs-write without scoping)
- Remediation:
  - none

### B56 - Control-UI cross-origin allow-all (allowedOrigins "*")

- Severity: HIGH
- Block: hardening
- Framework: Zero Trust / Control-UI Origin
- Scored: yes
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection
- What it checks: Control-UI cross-origin allow-all (allowedOrigins "*")
- Remediation:
  - none

### B57 - Plugin auto-approve (permissionMode=approve-all)

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege / Plugin Approval
- Scored: yes
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency, LLM03 Supply Chain
- What it checks: Plugin auto-approve (permissionMode=approve-all)
- Remediation:
  - none

### B58 - Unicode-obfuscated injection / hidden-text evasion

- Severity: HIGH
- Block: hardening
- Framework: Prompt Injection / Unicode Evasion
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection
- What it checks: Unicode-obfuscated injection / hidden-text evasion
- Remediation:
  - none

### B59 - Markdown-image data-exfil via remote URL

- Severity: MEDIUM
- Block: hardening
- Framework: Data Exfiltration / Markdown Injection
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM02 Sensitive Information Disclosure, LLM01 Prompt Injection
- What it checks: Markdown-image data-exfil via remote URL
- Remediation:
  - none

### B60 - Prompt self-replication / propagation directive

- Severity: HIGH
- Block: hardening
- Framework: Agentic Worm / Self-Replication
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection
- What it checks: Prompt self-replication / propagation directive
- Remediation:
  - none

### B61 - Cross-agent config snooping / credential theft

- Severity: HIGH
- Block: hardening
- Framework: Credential Theft / Supply Chain
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM02 Sensitive Information Disclosure, LLM01 Prompt Injection
- What it checks: Cross-agent config snooping / credential theft
- Remediation:
  - none

## Advisory checks

### B62 - Capability–intent mismatch (declared purpose vs actual behaviour)

- Severity: MEDIUM
- Block: advisory
- Framework: Excessive Agency / Inaccurate Capability Declaration
- Scored: no
- Confidence: MEDIUM
- OWASP: LLM06 Excessive Agency
- What it checks: Capability–intent mismatch (declared purpose vs actual behaviour)
- Remediation:
  - none

## Hardening checks

### B63 - Silent-instruction directive (hidden actions from user)

- Severity: HIGH
- Block: hardening
- Framework: Human Oversight / Transparency
- Scored: yes
- Confidence: HIGH
- OWASP: LLM09 Misinformation, LLM06 Excessive Agency
- What it checks: Silent-instruction directive (hidden actions from user)
- Remediation:
  - none

### B64 - Instruction-hierarchy override detector

- Severity: HIGH
- Block: hardening
- Framework: Prompt Injection / Instruction Hierarchy
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection
- What it checks: Instruction-hierarchy override detector
- Remediation:
  - none

### B65 - Conditional sleeper-trigger detector

- Severity: HIGH
- Block: hardening
- Framework: Prompt Injection / Conditional Trigger
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM06 Excessive Agency, LLM09 Misinformation
- What it checks: Conditional sleeper-trigger detector
- Remediation:
  - none

### B66 - Persona / role jailbreak detector

- Severity: HIGH
- Block: hardening
- Framework: Prompt Injection / Persona Injection
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM06 Excessive Agency, LLM09 Misinformation
- What it checks: Persona / role jailbreak detector
- Remediation:
  - none

### B67 - Per-source tool-output trust contracts

- Severity: MEDIUM
- Block: hardening
- Framework: Prompt Injection / Trust Boundary
- Scored: yes
- Confidence: MEDIUM
- OWASP: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure
- What it checks: Per-source tool-output trust contracts
- Remediation:
  - none

### B68 - apply_patch workspace-only restriction disabled

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Filesystem Write
- Scored: no
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: apply_patch workspace-only restriction disabled
- Remediation:
  - none

### B69 - exec inline-eval gate missing when exec enabled

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Inline Eval
- Scored: no
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: exec inline-eval gate missing when exec enabled
- Remediation:
  - none

### B70 - trustedProxy allowLoopback on non-loopback bind (header-spoof surface)

- Severity: LOW
- Block: hardening
- Framework: Zero Trust / Proxy Headers
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: trustedProxy allowLoopback on non-loopback bind (header-spoof surface)
- Remediation:
  - none

### B71 - gateway.nodes.denyCommands ineffective patterns (non-exact entries)

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / Node Commands
- Scored: no
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: gateway.nodes.denyCommands ineffective patterns (non-exact entries)
- Remediation:
  - none

### B72 - subagents.allowAgents wildcard (any agent as spawn target)

- Severity: LOW
- Block: hardening
- Framework: Least Privilege / Subagents
- Scored: no
- Confidence: HIGH
- OWASP: LLM06 Excessive Agency
- What it checks: subagents.allowAgents wildcard (any agent as spawn target)
- Remediation:
  - none

### B73 - mDNS full advertisement on non-loopback gateway bind

- Severity: LOW
- Block: hardening
- Framework: Least Privilege / Discovery
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: mDNS full advertisement on non-loopback gateway bind
- Remediation:
  - none

### B74 - Forged role/system block or false-provenance attribution in content

- Severity: HIGH
- Block: hardening
- Framework: Prompt Injection / Provenance Forgery
- Scored: yes
- Confidence: HIGH
- OWASP: none
- What it checks: Forged role/system block or false-provenance attribution in content
- Remediation:
  - none

### B75 - MCP tool-inheritance bypass — per-agent filter circumvented (attested)

- Severity: MEDIUM
- Block: hardening
- Framework: Least Privilege / MCP Tool Inheritance
- Scored: no
- Confidence: ATTESTED
- OWASP: none
- What it checks: MCP tool-inheritance bypass — per-agent filter circumvented (attested)
- Remediation:
  - none

### B76 - High-blast MCP tool-inheritance bypass (attested)

- Severity: HIGH
- Block: hardening
- Framework: Least Privilege / MCP Tool Inheritance
- Scored: yes
- Confidence: ATTESTED
- OWASP: none
- What it checks: High-blast MCP tool-inheritance bypass (attested)
- Remediation:
  - none

### B77 - Config-write audit log review (suspicious / unexpected writer)

- Severity: MEDIUM
- Block: hardening
- Framework: Audit Log / Config Provenance
- Scored: no
- Confidence: MEDIUM
- OWASP: none
- What it checks: Config-write audit log review (suspicious / unexpected writer)
- Remediation:
  - none

### B78 - Config-health integrity alert (observed suspicious signature)

- Severity: HIGH
- Block: hardening
- Framework: Config Integrity / Tamper Detection
- Scored: no
- Confidence: MEDIUM
- OWASP: none
- What it checks: Config-health integrity alert (observed suspicious signature)
- Remediation:
  - none

### B79 - Codex session approval-policy posture (approval=never)

- Severity: MEDIUM
- Block: hardening
- Framework: Human Approval
- Scored: no
- Confidence: MEDIUM
- OWASP: none
- What it checks: Codex session approval-policy posture (approval=never)
- Remediation:
  - none

## Advisory checks

### C3 - Backups of SOUL.md / memory

- Severity: LOW
- Block: advisory
- Framework: Backups
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: Backups of SOUL.md / memory
- Remediation:
  - none

### C4 - OpenClaw version / update hygiene

- Severity: LOW
- Block: advisory
- Framework: Patch hygiene
- Scored: no
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: OpenClaw version / update hygiene
- Remediation:
  - none

### C5 - Native binary PATH safety

- Severity: LOW
- Block: advisory
- Framework: Binary Integrity
- Scored: no
- Confidence: MEDIUM
- OWASP: LLM03 Supply Chain
- What it checks: Native binary PATH safety
- Remediation:
  - command: `chmod o-w,g-w <dir>`

### C6 - Hook-composition tool-policy drop (pre-v2026.6.10)

- Severity: LOW
- Block: advisory
- Framework: Patch hygiene
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: Hook-composition tool-policy drop (pre-v2026.6.10)
- Remediation:
  - none

### C032 - Proxy header trust when real-IP fallback is enabled

- Severity: LOW
- Block: advisory
- Framework: Gateway / Proxy Header Trust
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: Proxy header trust when real-IP fallback is enabled
- Remediation:
  - none

### C014 - Egress inventory (outbound-capable surface enumeration)

- Severity: LOW
- Block: advisory
- Framework: Egress Inventory
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: Egress inventory (outbound-capable surface enumeration)
- Remediation:
  - none

### C015 - Secrets-at-rest scan of the OpenClaw home

- Severity: MEDIUM
- Block: advisory
- Framework: Secrets / Filesystem
- Scored: no
- Confidence: MEDIUM
- OWASP: none
- What it checks: Secrets-at-rest scan of the OpenClaw home
- Remediation:
  - none

### C047 - Non-local MCP server endpoint (manual review)

- Severity: LOW
- Block: advisory
- Framework: MCP / External Endpoint Review
- Scored: no
- Confidence: HIGH
- OWASP: LLM03 Supply Chain
- What it checks: Non-local MCP server endpoint (manual review)
- Remediation:
  - none

### C048 - Cron scheduler persistence surface (top-level cron)

- Severity: LOW
- Block: advisory
- Framework: Persistence / Scheduled Execution
- Scored: no
- Confidence: HIGH
- OWASP: none
- What it checks: Cron scheduler persistence surface (top-level cron)
- Remediation:
  - none

### C074 - Injection-like text in HTML image attributes

- Severity: MEDIUM
- Block: advisory
- Framework: Prompt Injection / HTML Attribute
- Scored: no
- Confidence: HIGH
- OWASP: LLM01 Prompt Injection
- What it checks: Injection-like text in HTML image attributes
- Remediation:
  - none

## Compound risk chains

These paths are computed from multiple checks. They fire only when every leg is positively evidenced.

### RISK-01 - Untrusted sender can reach host execution

- Severity: CRITICAL
- Pattern: CRITICAL: public/group sender + exec/write/elevated tool.
- Chain: channel_label -> tool_label -> host / filesystem
- Why:
  The channel '{channel_label}' accepts messages from anyone (dmPolicy or groupPolicy is
  'open'). The agent also has {tool_label} enabled. Any anonymous actor can craft a
  message that causes the agent to execute code or mutate files on the host — no
  additional privilege escalation required.
- Fix:
  Lock every channel's dmPolicy and groupPolicy to 'allowlist' so only known, trusted
  senders can reach the agent. If open channels are required, remove or gate
  exec/write/elevated tools behind human approval (tools.exec.mode='ask' or
  tools.exec.security='ask').

### RISK-02 - Lethal Trifecta: untrusted input → sensitive data → outbound

- Severity: HIGH
- Pattern: HIGH: dirty input + sensitive data + outbound/exec (the explicit Trifecta path).
- Chain: input_label -> sensitive_label -> outbound_label
- Why:
  All three legs of the Lethal Trifecta are active simultaneously: the agent ingests
  untrusted content, has access to sensitive data, and can take outbound or exec actions.
  A single prompt-injection in the untrusted input is sufficient to exfiltrate secrets or
  execute arbitrary commands.
- Fix:
  Break at least one leg: (1) lock channels to allowlist and remove web/email input tools,
  OR (2) move secrets out of the agent's reach (use tools.exec.security='deny' for
  sensitive-data contexts), OR (3) gate ALL outbound/exec actions behind human approval.
  Keeping all three legs active is the highest-risk configuration possible.

### RISK-03 - No sandbox + untrusted ingress + exec/write tools

- Severity: HIGH
- Pattern: HIGH: sandbox off + untrusted ingress + fs_write/exec.
- Chain: ingress_label -> no execution sandbox -> exec/write directly on host
- Why:
  The execution sandbox is disabled (agents.defaults.sandbox.mode is 'off' or absent),
  meaning exec and fs_write tools run directly on the host OS. Combined with an untrusted
  ingress channel, a prompt-injection payload delivered via that channel can execute code
  or write files on the host without any containment.
- Fix:
  Enable the sandbox: set agents.defaults.sandbox.mode to 'non-main' or 'all', and
  configure agents.defaults.sandbox.docker (network='bridge', no broad host binds). If
  sandboxing is not possible, remove exec/write tools or lock all ingress channels to a
  strict allowlist.

### RISK-04 - Mutable agent identity + elevated/privileged tools

- Severity: HIGH
- Pattern: HIGH: mutable identity + elevated/privileged tools.
- Chain: identity spoofing or name-matching bypass -> elevated / exec tools -> privilege escalation
- Why:
  The agent's identity can be impersonated or matched by name
  (dangerouslyAllowNameMatching is enabled or B30 fails), AND elevated or exec tools are
  present. An attacker who spoofs the agent's name in a channel can cause the agent to
  treat their messages as coming from a trusted source and invoke privileged capabilities.
- Fix:
  Disable dangerouslyAllowNameMatching in all channel configurations and require
  cryptographic identity verification (e.g. token-based auth). Restrict elevated tool
  allowFrom to explicit, verified sender IDs — never '*' or name-matched identities.

### RISK-05 - Browser SSRF to private network + secrets reachable

- Severity: HIGH
- Pattern: HIGH: browser SSRF + secrets reachable.
- Chain: browser tool -> SSRF to private/internal network -> secrets / credentials exfiltration
- Why:
  The browser tool is allowed to reach private or internal network addresses
  (browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is set or B38 fails), and the agent
  has access to sensitive credentials. A prompt-injection payload in a web page can
  redirect the browser to internal services (metadata APIs, credential stores) and
  exfiltrate the retrieved data.
- Fix:
  Set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false (or remove it). Configure
  an explicit allowlist of permitted domains. Move credentials out of the agent's reach,
  or gate browser tool invocations behind human approval.

### RISK-06 - Control plane reachable from open/exposed surface

- Severity: CRITICAL
- Pattern: CRITICAL: control-plane reachable from an exposed/open surface.
- Chain: surface_label -> control-plane endpoint -> full agent takeover
- Why:
  The agent's control plane (management API, admin interface) is reachable from an open or
  untrusted surface (B32 fails). An attacker with access to an open channel or input
  vector can send commands directly to the control plane, potentially taking over the
  agent configuration, installing skills, or reading all secrets.
- Fix:
  Restrict control-plane access to loopback or a trusted VPN interface only. Lock all
  external channels to an allowlist. Enable strong auth (token ≥ 24 chars) on the control-
  plane endpoint and never expose it on a public or open interface.

### RISK-07 - Self-modification: writable identity/bootstrap + exec without approval

- Severity: HIGH
- Pattern: HIGH: writable bootstrap + exec/fs_write without approval.
- Chain: exec / fs_write tool (no approval gate) -> writable bootstrap/identity files -> agent identity rewritten → persistent compromise
- Why:
  Bootstrap or identity files (SOUL.md / AGENTS.md / TOOLS.md) are group- or world-
  writable (B20 or B22 fails), AND the agent has exec or fs_write tools enabled without a
  human approval gate. The agent can therefore rewrite its own instructions, identity, or
  installed skills — a single successful prompt-injection makes the compromise persistent
  across restarts.
- Fix:
  Run 'chmod 700 workspace/ && chmod 600 workspace/SOUL.md workspace/AGENTS.md
  workspace/TOOLS.md' to remove group/world write access. Also add an approval gate: set
  tools.exec.mode='ask'/'allowlist' (or tools.exec.security='ask') so every write action
  needs explicit human sign-off.

### RISK-08 - Session context shared across users in a multi-user channel

- Severity: MEDIUM
- Pattern: MEDIUM: session cross-user data leak + multi-user channel.
- Chain: multi-user channel -> session.dmScope='main' (shared session) -> cross-user data leak
- Why:
  The session scope is set to 'main' (or B39 fails), meaning all users in a multi-user
  channel share the same session context. A message from one user can inadvertently reveal
  another user's conversation history, personal data, or injected context.
- Fix:
  Set session.dmScope to 'per-user' so each DM participant receives an isolated session
  context. Audit channel configurations to ensure no group channel inadvertently shares
  session state across users.

### RISK-09 - Malicious installed skill can exfiltrate your data

- Severity: CRITICAL
- Pattern: CRITICAL: a malicious installed skill (B13 FAIL) + outbound egress = active exfiltration.
- Chain: malicious installed skill (B13) -> runs with full agent permissions -> outbound egress (channels / external skills) -> credential & data exfiltration
- Why:
  ClawSecCheck flagged an installed skill as malicious (B13 — the ClawHavoc class). Skills
  run with the agent's FULL permissions, and this agent has an outbound egress surface
  (messaging channels and/or external-service skills). The malicious skill can read your
  secrets and conversation data and send them out — this is an active exfiltration path,
  not theoretical.
- Fix:
  Uninstall the flagged skill(s) NOW (see the B13 finding for the name), and ROTATE every
  secret it could have reached — channel tokens, cloud keys, password managers. Only
  reinstall skills whose source you have read.

### RISK-10 - Powerful agent on an unmonitored host — a breach would be invisible

- Severity: MEDIUM
- Pattern: MEDIUM: a high-privilege agent on a host with NO detection monitoring.
- Chain: untrusted input reaches the agent -> agent can execute / write on the host -> no host detection (IDS / audit / file-integrity / EDR) -> a compromise would leave no trace
- Why:
  This agent can act on the host (exec / write / elevated tools) and is reachable by
  untrusted input, yet ClawSecCheck found NO host detection monitoring — no network IDS,
  no audit logging, no file-integrity monitor, and no endpoint/EDR sensor. If the agent
  were compromised via a prompt injection, the resulting activity would very likely go
  completely unseen.
- Fix:
  Add at least one host detection layer so a compromise is observable: enable auditd with
  watches on the agent's files, install a file-integrity monitor (AIDE), and/or deploy an
  EDR/IDS (Wazuh, Suricata). Alternatively, shrink the agent's blast radius (sandbox it,
  lock channels to an allowlist, remove exec/write tools) so an unseen compromise matters
  less.

### RISK-11 - Cross-agent trifecta reassembly (confused deputy)

- Severity: HIGH
- Pattern: HIGH: the trifecta reassembles ACROSS agents via the attested delegation graph.
- Chain: {entry} (untrusted input) -> {sens} (sensitive data) -> {outb} (outbound)
- Why:
  No single agent holds the full Lethal Trifecta, but the untrusted-input agent '{entry}'
  can drive a sensitive-data agent and an outbound agent across delegation edges that are
  not structural walls (raw passthrough / text filter / undeclared return). A single
  prompt-injection at the entry agent can orchestrate the others to exfiltrate secrets or
  take action — the trifecta reassembles across the graph (a confused-deputy chain).
- Fix:
  Break one edge: make the callee return a typed/structured value (a wall) so injected
  instructions and raw data cannot flow back, OR remove the delegation reach so '{entry}'
  cannot drive both a sensitive-data and an outbound agent.

### RISK-12 - Untrusted input + broad filesystem-write = tamper / persistence

- Severity: HIGH
- Pattern: HIGH: broad filesystem-write capability (B55) + untrusted ingress = tamper/persistence.
- Chain: ingress_label -> broad fs-write tool (unscoped, no approval gate) -> files overwritten → tamper / persistence implant
- Why:
  The agent is granted a filesystem-write tool (fs_write / apply_patch) that B55 found
  broadly reachable or ungated, AND untrusted content can reach the agent (an open channel
  or an input tool). A single prompt-injection in that untrusted input can drive arbitrary
  file writes — overwriting bootstrap or skill files to implant persistent instructions,
  or tampering with data the agent later trusts.
- Fix:
  Scope the write capability: set tools.exec.mode='ask' so writes need human sign-off,
  restrict tools.elevated.allowFrom to an explicit allowlist (no '*'), and lock ingress
  channels to 'allowlist'. Removing the fs_write/apply_patch grant entirely also breaks
  the chain.

### RISK-13 - Markdown-image exfil + writable memory/bootstrap = persistence / exfil

- Severity: HIGH
- Pattern: HIGH (RISK-13): markdown-image exfil + writable bootstrap/memory = persistence/exfil.
- Chain: remote markdown image URL with data-bearing query params -> writable bootstrap / memory files -> persisted payload + exfiltration channel
- Why:
  B59 shows that a remote markdown/image URL can carry data out of the agent context. If
  bootstrap or memory files are writable (B20 or B22 fails), the same attacker can write a
  payload or instruction back into files the agent reloads later. The result is a
  persistence-plus-exfil chain: steal data now, leave behind code or instructions that
  survive restart.
- Fix:
  Remove remote markdown/image URLs from untrusted content, keep bootstrap and memory
  files read-only, and require approval for any filesystem write that could persist
  instructions.

### RISK-14 - Wildcard-elevated sender + heartbeat = self-escalating autonomy loop

- Severity: HIGH
- Pattern: HIGH (RISK-14): wildcard-elevated sender + heartbeat = self-escalating loop.
- Chain: any sender via wildcard elevated provider(s): {', '.join(providers)} -> injected instruction invokes elevated tools -> heartbeat re-runs the agent unattended -> self-escalating privilege loop
- Why:
  A provider in tools.elevated.allowFrom is set to '*', so any sender on that channel can
  invoke elevated tools, and a heartbeat (agents.defaults.heartbeat or a per-agent
  heartbeat) makes the agent act on its own schedule. Together, a single prompt-injection
  from an untrusted sender can trigger elevated actions that the heartbeat keeps re-
  running unattended — a self-escalating autonomous privilege loop with no human in the
  path.
- Fix:
  Replace the '*' in tools.elevated.allowFrom with an explicit per-provider sender
  allowlist, and gate elevated execution (tools.exec.mode='ask'). If unattended autonomy
  is not required, disable the heartbeat. Breaking either leg breaks the chain.

### RISK-15 - Untrusted context + browser SSRF to private network = metadata/credential exfil

- Severity: HIGH
- Pattern: HIGH (RISK-15): untrusted-context ingress + browser SSRF to private network.
- Chain: untrusted message content (channels.<p>.contextVisibility='all') -> agent browses an attacker-controlled URL -> SSRF to internal metadata/credential endpoint -> data in tool output
- Why:
  A channel exposes full untrusted context to the agent
  (channels.<p>.contextVisibility='all', B26), and the browser is allowed to reach
  private/internal addresses (browser.ssrfPolicy.dangerouslyAllowPrivateNetwork, B38). A
  prompt-injection in an untrusted message can make the agent fetch an internal URL —
  cloud metadata or a credential store — and the response surfaces in tool output.
  OpenClaw has no built-in egress allowlist, so the attacker-fetch leg is structurally
  unconstrained.
- Fix:
  Set channels.<provider>.contextVisibility (or channels.defaults) to 'allowlist' or
  'allowlist_quote', and set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false
  with an explicit browser.ssrfPolicy.hostnameAllowlist. Breaking either leg breaks the
  chain.

### RISK-16 - Sandbox host-reach + plaintext gateway credential = control-plane takeover

- Severity: HIGH
- Pattern: HIGH (RISK-16): rw workspace + host-reaching bind + plaintext gateway password.
- Chain: rw workspace + {bind_label} -> agent reads plaintext gateway.auth.password from openclaw.json on the host -> authenticates to the control plane as admin -> takeover
- Why:
  The default agent sandbox grants workspaceAccess='rw' AND a docker bind that reaches the
  host filesystem broadly (docker.sock or a root-level source), so an exec-capable agent
  can read arbitrary host files. The gateway credential is stored in plaintext at
  gateway.auth.password in openclaw.json, so the agent can read it and authenticate to the
  control plane as admin — a sandbox weakness escalates to full control-plane takeover.
- Fix:
  Set agents.defaults.sandbox.workspaceAccess to 'ro' or 'none', remove docker.sock and
  root-level host binds from agents.defaults.sandbox.docker.binds, and stop storing
  gateway.auth.password in plaintext (use gateway.auth.mode='token' with a secret from the
  environment / a manager). Breaking any one leg breaks the chain.

### RISK-17 - Conditional sleeper trigger + scheduled execution = delayed RCE

- Severity: HIGH
- Pattern: HIGH (RISK-17): conditional sleeper trigger + scheduled exec = delayed RCE.
- Chain: conditional sleeper trigger in bootstrap or skill -> {schedule_label} keeps the agent running later -> exec/write tool fires when the trigger condition appears -> delayed RCE
- Why:
  B65 surfaces hidden instructions that wait for a future trigger. If the agent also runs
  on a schedule and can execute code or write files, the hidden payload can sit dormant
  until the trigger appears and then run without another review. That turns a delayed
  instruction into a delayed remote code execution path.
- Fix:
  Remove sleeper-trigger instructions, disable cron or heartbeat where they are not
  needed, and gate exec/write tools behind human approval.

### RISK-18 - Untrusted context + cron + heartbeat = persistent autonomous foothold

- Severity: HIGH
- Pattern: HIGH (RISK-18): contextVisibility=all + cron + heartbeat = persistent foothold.
- Chain: channel '{ch_label}' contextVisibility='all' → prompt injection via untrusted input -> injected instruction schedules a cron task (persistent scheduler surface) -> heartbeat re-executes cron task autonomously with no human review -> persistent autonomous foothold
- Why:
  A channel exposes full untrusted context to the agent
  (channels.<p>.contextVisibility='all'), a cron scheduler surface is active, and the
  agent runs autonomously on a heartbeat (agents.defaults.heartbeat). A prompt-injection
  in untrusted input can plant a cron task that the heartbeat re-executes indefinitely —
  no human approval is required after the initial injection. The result is a persistent
  autonomous foothold that survives restarts and continues running without further
  attacker interaction.
- Fix:
  Set channels.<provider>.contextVisibility (or channels.defaults.contextVisibility) to
  'allowlist' or 'allowlist_quote' to prevent untrusted content from reaching the agent.
  Disable the cron scheduler (remove the top-level 'cron' key) if scheduled tasks are not
  required. Set agents.defaults.heartbeat to a falsy value or add a human-approval gate
  for autonomous re-execution. Breaking any one leg breaks the chain.
