# Token Types

Canari generates deterministic synthetic values that look real but are non-production decoys.

## Built-in token types

- `api_key` -> `api_canari_<sig>`
- `credit_card` -> Luhn-valid test-style number
- `email` -> `canari-canary-...@sandbox.invalid`
- `phone` -> `+1-555-....`
- `ssn` -> synthetic formatted SSN-like value
- `aws_key` -> `AKIA...` synthetic key shape
- `stripe_key` -> `sk_test_CANARI_...`
- `github_token` -> `ghp_...`
- `document_id` -> `DOC-CANARI-...`
- `custom` -> document-id style fallback marker

## Design goals

- Clearly fake if inspected by humans.
- Realistic format so extraction tooling still targets it.
- Deterministic enough for exact-match detection and auditing.

## Placement strategy

Token metadata tracks:

- injection strategy (`context_appendix`, `system_prompt_comment`, `document_metadata`, etc.)
- injection location (where the decoy was planted)
- timestamp + optional tenant/app scope
