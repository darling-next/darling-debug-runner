# Darling debug runner

This repository owns the standalone Rust debugging runner used with Darling.

- Keep Darling checkout paths configurable; do not add dependencies on a
  particular workspace layout.
- Run `cargo test` and `cargo clippy --all-targets --all-features` before
  publishing changes.
- Workspace orchestration, tasks, and integration profiles live in the private
  `IlyaGulya/darling-workspace` repository.

