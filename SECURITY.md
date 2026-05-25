# Security Policy

## Supported Versions

AutoMyx CloudGuard is currently pre-1.0. Security fixes are handled on the latest `main` branch until versioned releases begin.

## Security Model

CloudGuard is designed as a local, read-only AWS triage tool.

- The CLI uses your local AWS credential chain.
- The browser UI is a report viewer only.
- AWS access keys are not entered into the browser UI.
- Reports stay on the user's machine unless the user chooses to share them.
- The scanner does not create, update, delete, stop, restart, detach, revoke, or remediate AWS resources.

## Reporting A Vulnerability

Please report security issues privately.

Email: contact@automyx.tech

Include:

- Affected version or commit
- Clear reproduction steps
- Expected vs actual behavior
- Whether the issue can expose credentials, account IDs, resource metadata, or report contents
- Suggested fix, if known

Please do not open a public GitHub issue for vulnerabilities that expose secrets, credentials, account data, or private infrastructure details.

## Sensitive Data Guidance

Do not attach real `automyx-report.json` files to public issues. Reports can contain AWS account IDs, ARNs, resource names, DNS names, public IPs, and security findings.

For public bug reports, use:

- Demo mode output
- Redacted screenshots
- Sanitized JSON snippets

## Scope

In scope:

- Credential leakage caused by this project
- Browser UI behavior that sends report data externally
- CLI behavior that performs unintended write actions
- Incorrect handling of report files that can expose local data
- Dependency vulnerabilities that affect the local scanner or report viewer

Out of scope:

- Findings produced from intentionally vulnerable AWS accounts
- AWS account compromise unrelated to this tool
- Social engineering
- Denial-of-service against local machines
- Issues requiring already-compromised AWS credentials

## Security Expectations

CloudGuard findings are triage signals. Users must validate findings before making production changes.
