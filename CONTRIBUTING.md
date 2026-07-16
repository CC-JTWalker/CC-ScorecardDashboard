# Contributing

Use a fork or topic branch and open a pull request against `main`. Direct pushes to `main` should be disabled through repository rules.

Before opening a pull request, run:

```bash
npm install
npm run test:all
```

Keep dependencies exact, avoid generated binaries in source control, and pin every GitHub Action to a full commit SHA. New network destinations, Electron privileges, IPC methods, file-system writes, and credential handling require an explicit security rationale and tests.

At least one approving review from a code owner should be required. The author should not approve their own change. Security reports follow SECURITY.md rather than the public issue tracker.
