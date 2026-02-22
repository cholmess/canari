import canari
import asyncio


def test_monitor_http_request_detects_egress_leak(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["aws_key"])[0]

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    events = honey.monitor_http_request(
        "POST",
        "https://api.example.com/submit",
        headers={"Authorization": f"Bearer {token.value}"},
        body={"hello": "world"},
    )

    assert len(events) == 1
    assert events[0].detection_surface == "network_egress"
    assert events_seen[0].canary_value == token.value


def test_wrap_httpx_client_patches_request(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    class DummyHttpClient:
        def request(self, method, url, **kwargs):
            return {"ok": True, "method": method, "url": url, "kwargs": kwargs}

    client = DummyHttpClient()
    honey.wrap_httpx_client(client)
    client.request("GET", f"https://x.example/?k={token.value}")

    assert len(events_seen) == 1


def test_wrap_httpx_client_patches_async_request(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    class DummyAsyncHttpClient:
        async def request(self, method, url, **kwargs):
            return {"ok": True, "method": method, "url": url, "kwargs": kwargs}

    client = DummyAsyncHttpClient()
    honey.wrap_httpx_client(client)
    asyncio.run(client.request("GET", f"https://x.example/?k={token.value}"))

    assert len(events_seen) == 1
