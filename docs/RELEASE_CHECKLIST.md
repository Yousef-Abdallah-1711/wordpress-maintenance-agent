# Release checklist

- [ ] Run the full mocked test suite on Python 3.12 and 3.13.
- [ ] Build sdist and wheel; inspect packaged skill resources and console entry point.
- [ ] Review dependency updates and GitHub Actions permissions.
- [ ] Verify no `.env`, private site config, reports, or credentials are staged.
- [ ] Verify PHP connector on supported WordPress versions and confirm denied access for anonymous and underprivileged users.
- [ ] Update changelog, version, and installation/report documentation.
- [ ] Tag a release and publish artifacts.
- [ ] Confirm weekly workflow is enabled and configured before claiming scheduled audits are active.
- [ ] Verify the public repository does not contain private reports or site data.
