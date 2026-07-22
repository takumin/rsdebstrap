# Security Policy

## Supported Versions

rsdebstrap is currently pre-1.0 and under active development. Security fixes are
applied to the latest `0.x` release line on the `main` branch. Older pre-release
snapshots are not maintained.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.

Instead, report them privately through GitHub's built-in private vulnerability
reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** to open a private advisory.

Direct link:
<https://github.com/takumin/rsdebstrap/security/advisories/new>

If you are unable to use GitHub's private vulnerability reporting, you may instead
email the maintainer at **takumiiinn@gmail.com**.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal profile YAML and the exact command, if relevant).
- The affected version or commit, and your environment (OS, bootstrap backend).
- Any suggested mitigation, if known.

## Disclosure Process

This is a single-maintainer project, so responses are made on a best-effort
basis. You can generally expect:

- An acknowledgement of your report within a few days.
- An assessment of the report and, if accepted, work toward a fix.
- Coordinated disclosure: a fix is prepared and released before details are made
  public, and your contribution is credited unless you prefer to remain anonymous.

Thank you for helping keep rsdebstrap and its users safe.
