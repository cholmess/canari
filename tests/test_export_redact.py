import csv
import json

import canari


def test_export_redacted(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    honey.alerter._channels = []
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(f"leak {token.value}", context={"conversation_id": "conv-red"})

    j = tmp_path / "redacted.jsonl"
    c = tmp_path / "redacted.csv"

    honey.export_alerts_jsonl(str(j), redact=True)
    honey.export_alerts_csv(str(c), redact=True)

    row = json.loads(j.read_text(encoding="utf-8").strip())
    assert row["canary_value"] == "[REDACTED]"
    assert token.value not in row["output_snippet"]

    with c.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["canary_value"] == "[REDACTED]"
