# Security Policy

Blink handles end-to-end encrypted secrets; vulnerability reports are taken seriously and handled promptly.

## Reporting a vulnerability

Email **security@malto.icu**, or use [GitHub's private vulnerability reporting](https://github.com/MALTOisHERE/onlyonce/security/advisories/new) for this repository.

Please include:

- A description of the issue and its impact
- Steps to reproduce (or a PoC)
- Affected version/commit, if known

Please do not open a public GitHub issue for security reports.

## Response

- Acknowledgement: within 72 hours
- A fix or mitigation timeline will follow once the report is triaged

## Scope

In scope: the Blink web app (`blink.malto.icu`), its API, and the browser extension in `extension/`.

Out of scope: third-party services Blink depends on (Cloudflare, Resend), social engineering, and denial-of-service testing against the live instance - use a local/self-hosted copy for load testing.

## Supported versions

Only the latest release of `main` is supported. See [Releases](https://github.com/MALTOisHERE/onlyonce/releases) for the current version.
