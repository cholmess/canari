# Alert Channels

Canari dispatches alerts to one or many channels. Dispatch failures never crash app code.

## Stdout

- Enabled by default in client initialization.
- Useful for local development and demo scenarios.

## Webhook

- Send structured JSON payloads to incident systems.
- Supports retries and optional HMAC signature headers.
- Signature headers:
  - `X-Canari-Signature`
  - `X-Canari-Signature-Version`

## Slack

- Send concise severity/token leak notifications via Slack webhook.
- Good for human-in-the-loop triage.

## File sink

- Write JSONL alerts to disk for local audit pipelines.

## Callback

- Register custom Python callback for internal routing.

## Rate limiting and filtering

- Set minimum dispatch severity.
- Apply rate limits (`window_seconds`, `max_dispatches`) to reduce noise during incident storms.
