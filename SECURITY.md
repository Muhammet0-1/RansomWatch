# Security Policy

## Supported versions

Security fixes are provided for the latest release on the default branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature when it is available. Otherwise,
contact the repository owner privately before publishing exploit details. Include the affected
version, operating system, reproduction steps, impact, and a minimal non-destructive proof of
concept.

Do not include malware samples, credentials, private user files, or data collected from systems
you do not own or administer.

## Security boundaries

RansomWatch is a local defensive signal generator. It does not attribute a filesystem event to a
process, prove that ransomware is present, stop encryption, recover files, or replace endpoint
protection and tested backups. Alerts require operator investigation.

The tool intentionally:

- refuses implicit home-directory monitoring;
- does not terminate or enumerate processes;
- does not inspect unrelated file contents;
- does not send telemetry or make network requests;
- creates deterministic, non-sensitive canaries with mode `0600`;
- refuses symlink, hard-link, ownership, and overly broad permission states;
- keeps alert output on standard output so the operator controls persistence.

Use a dedicated private directory, run as a regular user, and test recovery procedures separately.
