# Glossary

**Approval:** An approval is an operator decision that permits or refuses an action which policy does not decide automatically.

**Audit record:** An audit record is one JSON object that stores an action, decision, reason, context, and integrity data.

**Baseline:** A baseline is the accepted MCP tool inventory for one agent, server, and optional command hash.

**Bootstrap UI:** The bootstrap UI is the local console that manages setup and the service process before the service runs.

**Capture:** Capture is the observation and audit of traffic that passes through an AgentWall control path.

**Decoy:** A decoy is a synthetic credential whose appearance on an inspected path creates a high-confidence alert.

**Enforcement mode:** An enforcement mode selects monitor, guarded, or strict behavior for network decisions.

**Fleet:** A fleet is the set of declared agents that one AgentWall instance identifies and controls.

**Guarded mode:** Guarded mode blocks traffic when a matching deny rule or runtime control refuses it.

**Hash chain:** A hash chain links each audit record to the previous record so later changes become detectable.

**Interception:** Interception is the opt-in decryption of TLS traffic for configured hosts through a locally trusted CA.

**Monitor mode:** Monitor mode evaluates and records traffic without blocking it.

**Perimeter:** A perimeter is the Linux UID and network rule set that redirects an agent's outbound TCP through AgentWall.

**Policy:** A policy is the ordered set of rules that maps an action and context to a decision.

**Proxy:** A proxy is the AgentWall network service that receives client traffic, applies controls, and connects to allowed destinations.

**Sandbox:** A sandbox is the Linux process profile that uses Landlock and seccomp to restrict files, network ports, and system calls.

**Strict mode:** Strict mode blocks destinations that the configured allowlist does not name.

**Typed action:** A typed action is an allowlisted operator request with a validated schema and no raw shell string.
