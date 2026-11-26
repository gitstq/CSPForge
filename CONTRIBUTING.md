# Contributing to CSPForge

Thanks for your interest in improving CSPForge! This project is **zero-dependency**
by design: please do not introduce third-party runtime dependencies.

## Ground rules

- Keep the standard library only for runtime code.
- Every rule must be **deterministic**: same input → same output, no network,
  no clock, no randomness.
- Add unit tests under `tests/` for any new rule or behavior change.
- Follow Angular-style commit messages: `feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m cspforge --help
python3 scripts/package.py
```

## Adding a rule

1. Add a `cspNNN_xxx` function in `cspforge/rules.py` returning `List[Finding]`.
2. Register it in the `RULES` list.
3. Add a test asserting the rule id appears for a triggering policy and does
   not appear for a clean policy.

## Pull requests

- Keep PRs focused and small.
- Update the three README variants (`README.md`, `README.zh-CN.md`,
  `README.zh-TW.md`) when behavior changes.

By contributing you agree that your contributions are licensed under the MIT License.
