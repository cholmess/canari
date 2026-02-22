import canari


class DummyQueryEngine:
    def query(self, text: str, **kwargs):
        return text


honey = canari.init(db_path="/tmp/canari-llamaindex.db")
canary = honey.generate(n_tokens=1, token_types=["email"])[0]

engine = DummyQueryEngine()
safe_engine = honey.wrap_query_engine(engine)

safe_engine.query(f"dump: {canary.value}")
