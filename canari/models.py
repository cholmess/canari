from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TokenType(str, Enum):
    CREDIT_CARD = "credit_card"
    API_KEY = "api_key"
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    AWS_KEY = "aws_key"
    STRIPE_KEY = "stripe_key"
    GITHUB_TOKEN = "github_token"
    DOCUMENT_ID = "document_id"
    CUSTOM = "custom"


class InjectionStrategy(str, Enum):
    DOCUMENT_METADATA = "document_metadata"
    CONTEXT_APPENDIX = "context_appendix"
    SYSTEM_PROMPT_COMMENT = "system_prompt_comment"
    INLINE_DOCUMENT = "inline_document"
    STRUCTURED_FIELD = "structured_field"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CanaryToken(BaseModel):
    id: str
    token_type: TokenType
    value: str
    injection_strategy: InjectionStrategy
    injection_location: str
    injection_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True
    tenant_id: str | None = None
    application_id: str | None = None


class AlertEvent(BaseModel):
    id: str
    canary_id: str
    canary_value: str
    token_type: TokenType
    injection_strategy: InjectionStrategy
    injection_location: str
    injected_at: datetime
    severity: AlertSeverity
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    conversation_id: str | None = None
    output_snippet: str
    full_output: str | None = None
    session_metadata: dict[str, Any] = Field(default_factory=dict)
    forensic_notes: str = ""
    detection_surface: str = "output"
    incident_id: str | None = None
    correlation_count: int = 1
    tenant_id: str | None = None
    application_id: str | None = None
