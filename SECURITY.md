# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately using one of the following methods:

1. **GitHub Private Vulnerability Reporting:** Use the [Security Advisories](https://github.com/ScottsSecondAct/AutomaGuard/security/advisories/new) page to submit a private report directly on GitHub.
2. **Email:** Send details to **scott@ScottsSecondAct.com**.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

### What to Expect

- **Acknowledgment** within 72 hours of your report
- **Status update** within 7 days with an initial assessment
- **Resolution timeline** communicated once the issue is confirmed
- Credit in the release notes (unless you prefer to remain anonymous)

### Scope

AutomaGuard is a policy compilation and enforcement engine for AI agents. Relevant security concerns include:

- **Bytecode parsing** — malicious `.aegisc` files that trigger unexpected behavior in the runtime deserializer
- **Policy evaluation** — crafted event payloads that cause incorrect verdicts (false allows or false denies)
- **Denial of service** — policy files or event streams that trigger excessive CPU or memory usage in the runtime evaluator or state machines
- **Python binding boundary** — inputs via the pyo3 SDK that bypass enforcement or cause panics in the Rust layer
- **Audit log integrity** — any mechanism that allows verdict records to be silently dropped or mutated after the fact

### Out of Scope

- Issues requiring physical access to the machine running the agent
- Social engineering
- Vulnerabilities in upstream dependencies that already have published fixes (please check first)
- Cosmetic or usability issues in the compliance dashboard
