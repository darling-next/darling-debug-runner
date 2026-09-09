# Darling debug runner

This repository owns the standalone Rust debugging runner used with Darling.

- Keep Darling checkout paths configurable; do not add dependencies on a
  particular workspace layout.
- Run `cargo test` and `cargo clippy --all-targets --all-features` before
  publishing changes.
- Workspace orchestration, tasks, and integration profiles live in the private
  `IlyaGulya/darling-workspace` repository.
- For workspace diagnostics, use the manifest's `mise run dw dev run` scenarios;
  they own pinned West initialization, executor selection, observation and
  prefix lifecycle. Standalone runner commands remain for runner development.
- Publish `BUNDLE` when capture storage is created. Active West jobs discover
  registered stdout/stderr automatically; do not require callers to guess
  timestamped log paths. `--forward-output` is completion-time replay.
- Preserve bounded capture and explicit incompleteness for unreadable mappings.
  Expected payload timeout in the exact-capture diagnostic is distinct from
  diagnostic failure and from the archive's `exact_complete` flag.
- Never add global Darling process kills or a second prefix lifecycle owner.
  Preserve evidence before owner cleanup; log silence is not proof of a hang.
- A sibling runner may be outside the source forest handoff. Commit its owned
  changes on the canonical fix branch, refresh the actual keeper bundle and
  verify that branch tip explicitly. No publication without explicit approval.

