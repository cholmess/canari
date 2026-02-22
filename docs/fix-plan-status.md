# Canari Fix Plan Status

Date: 2026-02-22

## Completed in repository

- [x] Attack demo scaffold created at `examples/attack_demo/`:
  - [x] `README.md`
  - [x] `app.py`
  - [x] `.env.example`
  - [x] `requirements.txt`
  - [x] `attack_demo.tape` (for GIF rendering with VHS)
- [x] README rewritten for launch order (`problem -> insight -> visual -> install -> quickstart -> demo`) in `README.md`.
- [x] README reduced below 150 lines (current: 125).
- [x] Advanced sections moved out of README into:
  - [x] `docs/cli-reference.md`
  - [x] `docs/enterprise.md`
  - [x] `docs/alert-channels.md`
  - [x] `docs/threat-intelligence.md`
  - [x] `docs/integration-guide.md`
  - [x] `docs/token-types.md`
- [x] Show HN draft created in `docs/show-hn.md`.
- [x] PyPI metadata improved in `pyproject.toml` (license + classifiers).
- [x] `.gitignore` updated to ignore local plan and demo env file.
- [x] Test suite passes locally: `pytest -q`.

## Pending external/runtime tasks

- [ ] Build package artifacts (`python -m build`) once `build` module is installed.
- [ ] Publish to PyPI (`twine upload ...`) from a network-enabled environment.
- [ ] Render demo GIF from `examples/attack_demo/attack_demo.tape` once `vhs` is installed.
- [ ] Validate attack demo end-to-end with a real `OPENAI_API_KEY`.
- [ ] Fill `.pypirc` credentials (template in `.pypirc.example`).

## Exact closeout commands

```bash
cp .pypirc.example .pypirc
# edit .pypirc with real tokens

python -m pip install build
python -m build
twine upload --config-file .pypirc --repository pypi dist/*

# GIF
vhs examples/attack_demo/attack_demo.tape
# expected output:
# docs/assets/attack-demo.gif

# E2E demo
cd examples/attack_demo
cp .env.example .env
# set OPENAI_API_KEY in .env
pip install -r requirements.txt
python app.py
```
