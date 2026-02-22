import asyncio

import canari


class DummyCompletions:
    def __init__(self, text: str):
        self.text = text

    def create(self, **kwargs):
        return {"choices": [{"message": {"content": self.text}}]}


class DummyResponses:
    def __init__(self, text: str):
        self.text = text

    def create(self, **kwargs):
        return {"output_text": self.text}


class DummyChat:
    def __init__(self, text: str):
        self.completions = DummyCompletions(text)


class DummyOpenAI:
    def __init__(self, text1: str, text2: str):
        self.chat = DummyChat(text1)
        self.responses = DummyResponses(text2)


class DummyRunnable:
    def __init__(self, value: str):
        self.value = value

    def invoke(self, input, *args, **kwargs):
        return {"output": self.value}

    async def ainvoke(self, input, *args, **kwargs):
        return {"output": self.value}

    def batch(self, inputs, *args, **kwargs):
        return [{"output": self.value} for _ in inputs]

    async def abatch(self, inputs, *args, **kwargs):
        return [{"output": self.value} for _ in inputs]


def test_patch_openai_client_dispatches(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["stripe_key"])[0]

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    client = DummyOpenAI(f"x {token.value}", f"y {token.value}")
    patched = honey.patch_openai_client(client)
    assert patched["patched_endpoints"] == 2

    client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
    client.responses.create(model="gpt-4o-mini", input="hello")

    assert len(events_seen) == 2


def test_wrap_runnable_dispatches_sync_and_async(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    safe = honey.wrap_runnable(DummyRunnable(f"leak {token.value}"))
    safe.invoke({"q": "one"})
    safe.batch([{"q": "a"}, {"q": "b"}])
    asyncio.run(safe.ainvoke({"q": "two"}))
    asyncio.run(safe.abatch([{"q": "c"}]))

    assert len(events_seen) == 5
