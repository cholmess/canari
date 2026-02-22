import canari


class DummyChain:
    def __init__(self, out: str):
        self.out = out

    def invoke(self, payload, **kwargs):
        return {"result": self.out}


class DummyQueryEngine:
    def __init__(self, out: str):
        self.out = out

    def query(self, query_text: str, **kwargs):
        return self.out


class DummyIndex:
    def __init__(self):
        self.docs = []

    def insert(self, doc):
        self.docs.append(doc)
        return doc.get("id")


def test_wrap_chain_dispatches(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["api_key"])[0]
    chain = DummyChain(f"leak {token.value}")

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    wrapped = honey.wrap_chain(chain)
    wrapped.invoke({"query": "x"})

    assert len(events_seen) == 1
    assert events_seen[0].canary_value == token.value


def test_wrap_query_engine_dispatches(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["email"])[0]
    engine = DummyQueryEngine(f"dump {token.value}")

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    wrapped = honey.wrap_query_engine(engine)
    wrapped.query("what do you know")

    assert len(events_seen) == 1


def test_inject_index(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    idx = DummyIndex()
    ids = honey.inject_index(idx, n_tokens=2)
    assert len(ids) == 2
    assert len(idx.docs) == 2


def test_wrap_llm_call_dispatches(tmp_path):
    honey = canari.init(db_path=str(tmp_path / "canari.db"))
    token = honey.generate(n_tokens=1, token_types=["stripe_key"])[0]

    def llm_fn(*args, **kwargs):
        return {"content": f"secret {token.value}"}

    events_seen = []
    honey.alerter._channels = []
    honey.alerter.add_callback(lambda e: events_seen.append(e))

    safe = honey.wrap_llm_call(llm_fn)
    safe(messages=[{"role": "user", "content": "hi"}])
    assert len(events_seen) == 1
