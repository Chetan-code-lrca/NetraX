# Security Policy

## Supported versions

Security fixes are applied to the current default branch. Older commits and
unreleased branches are not guaranteed to receive security updates.

## Reporting a vulnerability

Please do not publish exploitable details, credentials, private packet
captures, or customer/network data in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use
the repository's Security tab to submit a private report. Otherwise, contact
the repository owner through GitHub and request a private disclosure channel.
Please include:
- affected commit or release;
- impact and prerequisites;
- a minimal reproduction that uses synthetic or sanitized data;
- any proposed mitigation.

Please allow maintainers a reasonable opportunity to investigate and prepare a
fix before public disclosure. This project does not currently publish a
formal response-time SLA.

## Data and deployment precautions

- NetraX is an unauthenticated analysis API intended for a trusted local
  operator. The default Docker Compose dashboard binding is loopback-only.
- Do not expose the dashboard/API to an untrusted network without adding
  authentication, TLS, request throttling, access controls, and a documented
  retention/deletion policy.
- Analyze only captures you are authorized to collect and process.
- PCAPs, flow CSVs, source/destination addresses, DNS names, and generated
  reports can contain sensitive network or personal data. Keep them out of
  public issues and repositories.
- Treat .joblib/pickle model artifacts as executable trusted code. Never load
  model files uploaded by untrusted users.
- Detection output is an investigation lead, not proof of compromise or a
  substitute for incident-response validation.
