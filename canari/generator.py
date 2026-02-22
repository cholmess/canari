from __future__ import annotations

import base64
import hashlib
import random
import string
import uuid
from datetime import datetime, timezone

from canari.models import CanaryToken, InjectionStrategy, TokenType


def _luhn_checksum(number: str) -> int:
    digits = [int(d) for d in number]
    parity = len(digits) % 2
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10


def _luhn_complete(partial: str) -> str:
    for check in range(10):
        if _luhn_checksum(f"{partial}{check}") == 0:
            return f"{partial}{check}"
    raise RuntimeError("failed to produce luhn-valid number")


def _short_sig(token_id: str, length: int = 8) -> str:
    raw = hashlib.sha256(token_id.encode("utf-8")).digest()
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()[:length]


def _rand_alnum(length: int) -> str:
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def _gen_credit_card(token_id: str) -> str:
    # Use a well-known test prefix and embed deterministic signature bytes.
    sig_digits = "".join(str((ord(c) % 10)) for c in _short_sig(token_id, 6))
    partial = f"4111{sig_digits}".ljust(15, "0")[:15]
    return _luhn_complete(partial)


def _gen_api_key(token_id: str) -> str:
    return f"api_canari_{_short_sig(token_id, 16)}"


def _gen_email(token_id: str) -> str:
    return f"canari-canary-{token_id[:12]}@sandbox.invalid"


def _gen_phone(token_id: str) -> str:
    suffix = int(hashlib.md5(token_id.encode("utf-8")).hexdigest()[:2], 16) % 100
    return f"+1-555-01{suffix:02d}"


def _gen_ssn(token_id: str) -> str:
    digits = int(hashlib.sha1(token_id.encode("utf-8")).hexdigest()[:8], 16)
    area = (digits % 899) + 1
    group = ((digits // 899) % 99) + 1
    serial = ((digits // (899 * 99)) % 9999) + 1
    return f"{area:03d}-{group:02d}-{serial:04d}"


def _gen_aws_key(token_id: str) -> str:
    payload = _short_sig(token_id, 16).upper()
    return f"AKIA{payload}"[:20]


def _gen_stripe_key(token_id: str) -> str:
    return f"sk_test_CANARI_{_short_sig(token_id, 18)}"


def _gen_github_token(token_id: str) -> str:
    return f"ghp_{_short_sig(token_id, 36)}"


def _gen_document_id(token_id: str) -> str:
    return f"DOC-CANARI-{_short_sig(token_id, 12).upper()}"


_GENERATORS = {
    TokenType.CREDIT_CARD: _gen_credit_card,
    TokenType.API_KEY: _gen_api_key,
    TokenType.EMAIL: _gen_email,
    TokenType.PHONE: _gen_phone,
    TokenType.SSN: _gen_ssn,
    TokenType.AWS_KEY: _gen_aws_key,
    TokenType.STRIPE_KEY: _gen_stripe_key,
    TokenType.GITHUB_TOKEN: _gen_github_token,
    TokenType.DOCUMENT_ID: _gen_document_id,
    TokenType.CUSTOM: _gen_document_id,
}


class CanaryGenerator:
    def __init__(self, default_strategy: InjectionStrategy = InjectionStrategy.CONTEXT_APPENDIX):
        self.default_strategy = default_strategy

    def generate(
        self,
        token_type: TokenType,
        *,
        injection_strategy: InjectionStrategy | None = None,
        injection_location: str = "unassigned",
        metadata: dict | None = None,
    ) -> CanaryToken:
        token_id = str(uuid.uuid4())
        value = _GENERATORS[token_type](token_id)
        return CanaryToken(
            id=token_id,
            token_type=token_type,
            value=value,
            injection_strategy=injection_strategy or self.default_strategy,
            injection_location=injection_location,
            injection_timestamp=datetime.now(timezone.utc),
            metadata=metadata or {},
        )

    def generate_many(
        self,
        token_types: list[TokenType],
        *,
        injection_strategy: InjectionStrategy | None = None,
        injection_location: str = "unassigned",
        metadata: dict | None = None,
    ) -> list[CanaryToken]:
        return [
            self.generate(
                token_type,
                injection_strategy=injection_strategy,
                injection_location=injection_location,
                metadata=metadata,
            )
            for token_type in token_types
        ]
