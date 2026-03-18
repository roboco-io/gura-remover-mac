# Repository Guidelines

## Project Structure & Module Organization
This repository is currently in an early planning stage. The main product specification lives in `docs/PRD.md`, which defines the macOS CLI direction for the project. Treat `docs/` as the source of truth for scope, commands, and expected behavior until implementation files are added. Internal tool state may appear under `.omc/` and `.omx/`; do not depend on or edit those directories unless the task explicitly targets agent tooling.

## Build, Test, and Development Commands
There is no committed build or test toolchain yet. Do not invent commands in code, docs, or PRs. When implementation is added, document real commands here and in `README.md`.

Current useful commands:
- `rg --files` to inspect repository contents quickly.
- `sed -n '1,200p' docs/PRD.md` to review the current product requirements.

## Coding Style & Naming Conventions
Match the language and formatter introduced by the implementation. Until then:
- Use Markdown headings and short, direct prose in documentation.
- Keep filenames lowercase with clear names, for example `docs/architecture.md`.
- Prefer ASCII unless a file already uses Korean text, as `docs/PRD.md` does.
- Keep CLI terminology consistent with the PRD: `scan`, `list`, `remove`, `restore`, `rollback`.

## Testing Guidelines
No automated tests are present yet. When adding code:
- Add tests in a dedicated `tests/` directory or the language-standard test location.
- Name tests after the behavior they verify, for example `scan_filters_high_risk_items`.
- Cover destructive flows such as delete, rollback, privilege escalation, and log output before merging.

## Commit & Pull Request Guidelines
Git history is not available in this workspace, so use clear imperative commit messages such as `Add scan command skeleton` or `Revise CLI safety requirements in PRD`. Keep commits focused.

PRs should include:
- A short summary of the change.
- The affected paths, for example `docs/PRD.md`.
- Test evidence or a note that no runnable tests exist yet.
- Screenshots only for documentation images or future UI assets; this project is currently CLI-first.

## Security & Safety Notes
This project targets system cleanup on macOS. Prefer safe defaults, explicit confirmation for destructive actions, minimal logging of sensitive data, and documentation of any command that requires elevated privileges.
