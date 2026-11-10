# Contributing

1. Create a focused branch and explain the behavior being changed.
2. Keep all audits read-only and keep remote content untrusted.
3. Add mocked tests for network and security behavior; do not run destructive tests against production sites.
4. Run `python -m pytest` and build the package before submitting.
5. Update user-facing docs and the changelog when behavior changes.

Pull requests should include the test output and any platform-specific checks that could not be run.
