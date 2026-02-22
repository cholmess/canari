import canari


class DummyRunnable:
    def __init__(self, text: str):
        self.text = text

    def invoke(self, input, *args, **kwargs):
        return {"output": self.text}


honey = canari.init(db_path="/tmp/canari-runnable.db")
canary = honey.generate(n_tokens=1, token_types=["api_key"])[0]

safe_runnable = honey.wrap_runnable(DummyRunnable(f"leak {canary.value}"))
print(safe_runnable.invoke({"question": "hello"}))
