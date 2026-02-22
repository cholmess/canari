import re

from canari.generator import CanaryGenerator, _luhn_checksum
from canari.models import TokenType


def test_generate_supported_types():
    gen = CanaryGenerator()
    for token_type in [
        TokenType.CREDIT_CARD,
        TokenType.EMAIL,
        TokenType.PHONE,
        TokenType.SSN,
        TokenType.AWS_KEY,
        TokenType.STRIPE_KEY,
        TokenType.GITHUB_TOKEN,
        TokenType.API_KEY,
    ]:
        token = gen.generate(token_type)
        assert token.token_type == token_type
        assert token.value


def test_credit_card_is_luhn_valid():
    gen = CanaryGenerator()
    token = gen.generate(TokenType.CREDIT_CARD)
    digits = re.sub(r"\D", "", token.value)
    assert len(digits) == 16
    assert _luhn_checksum(digits) == 0


def test_email_uses_invalid_tld():
    gen = CanaryGenerator()
    token = gen.generate(TokenType.EMAIL)
    assert token.value.endswith(".invalid")
    assert "canari-canary-" in token.value


def test_aws_key_shape():
    gen = CanaryGenerator()
    token = gen.generate(TokenType.AWS_KEY)
    assert token.value.startswith("AKIA")
    assert len(token.value) == 20
