# Security Policies and Procedures

This document outlines security procedures and general policies for the
`GhidraMSC` project.

- [Disclosing a security issue](#disclosing-a-security-issue)
- [Vulnerability management](#vulnerability-management)
- [Maintenance scope](#maintenance-scope)
- [Suggesting changes](#suggesting-changes)

## Disclosing a security issue

The `GhidraMSC` maintainers take all security issues in the project
seriously. Thank you for improving the security of `GhidraMSC`. We
appreciate your dedication to responsible disclosure and may acknowledge
your contributions.

`GhidraMSC` leverages GitHub's private vulnerability reporting.

To learn more about this feature and how to submit a vulnerability report,
review [GitHub's documentation on private reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Here are some helpful details to include in your report:

- a detailed description of the issue and its impact
- the steps required to reproduce the issue
- versions of the project that may be affected by the issue
- if known, any mitigations for the issue

For GhidraMSC-specific report details and sample-sharing guidance, see
[CONTRIBUTING.md](CONTRIBUTING.md#project-specific-guidance).

A maintainer may acknowledge the report, and may send a more detailed response
indicating the next steps in handling your report.

If you are unable to submit a vulnerability report through GitHub, or need to
follow up on a report that has not received a response, please reach out to Cisco's
open source security contact at
[oss-security@cisco.com](mailto:oss-security@cisco.com).

After the initial reply to your report, the maintainers may endeavor to keep
you informed of the progress towards a fix and full announcement, and may ask
for additional information or guidance.

## Vulnerability management

When the maintainers receive a disclosure report, they may assign it to a
primary handler.

This person may coordinate the fix and release process, which may involve the
following steps:

- confirming the issue
- determining affected versions of the project
- auditing code to find any potential similar problems
- preparing fixes for all releases under maintenance

## Maintenance scope

Fixes focus on the latest published GhidraMSC release; older releases may not
receive security updates. There is no guaranteed response or fix timeline.

## Suggesting changes

If you have suggestions on how this process could be improved please submit an
issue or pull request. For non-security bugs, see [CONTRIBUTING.md](CONTRIBUTING.md).
