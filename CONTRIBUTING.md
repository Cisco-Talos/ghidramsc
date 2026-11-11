# How to Contribute

Thanks for your interest in contributing to `GhidraMSC`! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
may endeavor to review incoming issues and pull requests, and may
close any lingering issues or pull requests after inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-talos/ghidramsc/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it in a public GitHub
issue or pull request. Instead, please see security procedures in
[SECURITY.md](SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and
may reserve breaking changes until the next major version release.

## Other Ways to Contribute

We welcome anyone that wants to contribute to `GhidraMSC` to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
	_[Reporting Issues](#reporting-issues)_ section, providing feedback to the
	issue's author on what might be missing.
- Review and update the existing content of our
	[documentation](USAGE.md) with up-to-date instructions and code samples.
- Review existing pull requests, and testing patches against real existing
	applications that use `GhidraMSC`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `GhidraMSC`!

## Project-specific guidance

GhidraMSC grew out of a research project and is maintained by one researcher
as time permits. Review, merges, fixes, and releases do not have a guaranteed
schedule. The maintainer may decline changes that would be difficult to maintain
or are outside the project's scope.

For a reproducible bug, include the GhidraMSC and Ghidra versions, operating
system, Python version if relevant, and interface used (CLI, HTTP, headless MCP,
or GUI plugin MCP). Describe reproduction steps, expected behavior, and actual
results. A small, sanitized example or relevant log excerpt is helpful. Do not
post credentials, private project data, proprietary binaries, or undisclosed
vulnerability details in a public issue.

For private security reports, share only samples and project data you are
authorized to provide; a minimal sanitized reproducer is preferred.

For a substantial change, open an issue first to discuss scope. Keep pull
requests focused, explain behavior changes, and update affected documentation.
Preserve existing copyright and license notices. New source files should use
the Apache 2.0 header with an accurate copyright owner. Submit only material you
are authorized to distribute under the [Apache 2.0 license](LICENSE).

Keep discussion respectful and focused; the maintainer may close abusive or
off-topic discussions.

## Testing

Use Python 3.10 or newer and `pytest` 8 or newer. Run relevant checks from the
repository root; the full Python suite is:

```text
python -m pytest tests/ -v
```

The Python suite mocks the Ghidra Java API and needs no JVM or project. Java
handler/dispatcher tests are build-time checks described in the
[plugin build instructions](README.md#installing-the-plugin). Neither suite
is live-project acceptance; runtime claims require a separate test against a
disposable Ghidra project. See [testing guidance](README.md#testing). If a check
cannot run in your environment, say so in the pull request.
