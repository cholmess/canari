import canari


def test_threat_share_bundle_import_and_match(tmp_path):
    db_a = tmp_path / "a.db"
    db_b = tmp_path / "b.db"

    src = canari.init(db_path=str(db_a))
    src.alerter._channels = []
    token = src.generate(n_tokens=1, token_types=["api_key"])[0]
    src.scan_output(f"leak {token.value}", context={"conversation_id": "conv-a"})

    bundle = src.export_threat_share_bundle(limit=100)
    assert bundle["schema"] == "canari-threat-share-v1"
    assert bundle["feed"]["unique_signatures"] >= 1

    dst = canari.init(db_path=str(db_b))
    dst.alerter._channels = []
    imported = dst.import_threat_share_bundle(bundle, source="community")
    assert imported["imported"] >= 1

    signatures = dst.network_signatures(limit=100, offset=0)
    assert len(signatures) >= 1

    dst_token = dst.generate(n_tokens=1, token_types=["api_key"])[0]
    dst.scan_output(f"leak {dst_token.value}", context={"conversation_id": "conv-b"})
    local_sig = dst.local_threat_feed(limit=100)["signatures"][0]["signature"]
    dst.import_threat_share_bundle(
        {"signatures": [{"signature": local_sig, "count": 1, "token_type": "api_key"}]},
        source="manual-test",
    )
    matches = dst.network_threat_matches(local_limit=100, network_limit=100)
    assert matches["match_count"] >= 1
    assert matches["network_signatures_considered"] >= 1


def test_opted_in_network_match_dispatches_shadow_alert(tmp_path):
    db = tmp_path / "canari.db"
    honey = canari.init(db_path=str(db))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    # Build a local signature first.
    honey.alerter._channels = []
    honey.scan_output(f"repeat {token.value}", context={"conversation_id": "conv-seed"})
    signature = honey.local_threat_feed(limit=100)["signatures"][0]["signature"]
    honey.registry.upsert_network_signatures(
        [
            {
                "signature": signature,
                "count": 3,
                "token_type": "api_key",
                "surface": "llm_output",
                "severity": "low",
            }
        ],
        source="community",
    )

    events = []
    honey.alerter.add_callback(lambda event: events.append(event))
    honey.set_threat_sharing_opt_in(True)
    honey.scan_output(f"repeat {token.value}", context={"conversation_id": "conv-live"})

    assert len(events) >= 2
    assert any("network_signature_match=" in e.forensic_notes for e in events)
    assert any(row["action"] == "network_signature_match" for row in honey.audit_log(limit=50))
