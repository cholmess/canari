import csv
import json

import canari


def test_export_jsonl_and_csv(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    honey.scan_output(
        f"leak {token.value}",
        context={"conversation_id": "conv-export"},
    )

    jsonl_path = tmp_path / "alerts.jsonl"
    csv_path = tmp_path / "alerts.csv"

    n_jsonl = honey.export_alerts_jsonl(str(jsonl_path), limit=100)
    n_csv = honey.export_alerts_csv(str(csv_path), limit=100)

    assert n_jsonl == 1
    assert n_csv == 1

    lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["conversation_id"] == "conv-export"

    with csv_path.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["conversation_id"] == "conv-export"
