# TRACE Desktop

This is the separately named Windows/macOS desktop product source. Version
`0.1.0` is a security and packaging foundation, not a finished offline client.

Implemented: hardened Electron process isolation, denied browser permissions,
strict local CSP, OS-protected random device key, AES-256-GCM authenticated local
store, atomic writes, server reachability, responsive branded shell and distinct
Windows/macOS artifact naming.

Not implemented: device enrollment/revocation, encrypted SQLite records,
snapshot/operation/command sync APIs, attachments, complete project modules,
automatic updates, signing/notarization and acceptance-tested installers.

Do not distribute an unsigned artifact as a production TRACE release.
