# Contributing to Kyvern

Thanks for your interest. Kyvern records, verifies and reports on the
decisions an autonomous system makes. Contributions that make that record more
trustworthy, or easier to adopt on a real robot, are the most welcome.

## Before you start

- For anything bigger than a small fix, open an issue or a
  [discussion](https://github.com/altunbulakemre75/kyvern/discussions) first,
  so we can agree on the approach before you write the code.
- Found a way to make a changed, deleted or forged record pass verification?
  Do not open a public issue; see [SECURITY.md](SECURITY.md).
- In scope: recording, verification, anchoring, reporting, integrations (ROS2,
  MCP) and docs. Out of scope: weapons or counter-UAS functionality.

## Development setup

```bash
git clone https://github.com/altunbulakemre75/kyvern.git
cd kyvern
python -m venv .venv            # then activate it
pip install -r requirements.txt # editable install with every extra
pytest
ruff check .
pyright                         # type check of kyvern, cli, services and shared
```

CI runs ruff and the tests on Python 3.10–3.13, type-checks with pyright,
checks that the core install (`pip install .`, no extras) works, and runs
the tests with only the `dev` extra installed. Tests that need an extra skip themselves without it.

## Making a change

- Write the test first and watch it fail, then make it pass.
- One change per pull request. Say what was wrong and how you checked the fix.
- Add a line under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) for anything a
  user would notice.
- Docs are in English; update README and `docs/` when behaviour changes.
- `main` is protected: a pull request merges once every CI check passes.
- Never commit signing keys, chains with real data, or anything from `~/.kyvern`.

Changes to what is signed (the fields of a record, `canonical_json()`) break
the verification of existing chains. Please discuss them in an issue first.

## License

Contributions are accepted under the Apache License 2.0, as section 5 of
[LICENSE](LICENSE) describes.

## Code of conduct

This project follows its [code of conduct](CODE_OF_CONDUCT.md).
