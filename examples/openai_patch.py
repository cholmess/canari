import canari


class _DummyCompletions:
    def __init__(self, text: str):
        self.text = text

    def create(self, **kwargs):
        return {"choices": [{"message": {"content": self.text}}]}


class _DummyChat:
    def __init__(self, text: str):
        self.completions = _DummyCompletions(text)


class DummyOpenAIClient:
    def __init__(self, text: str):
        self.chat = _DummyChat(text)


honey = canari.init(db_path="/tmp/canari-openai.db")
canary = honey.generate(n_tokens=1, token_types=["stripe_key"])[0]

client = DummyOpenAIClient(f"leaked: {canary.value}")
honey.patch_openai_client(client)

resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
print(resp)
