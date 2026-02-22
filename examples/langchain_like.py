import canari


class DummyChain:
    def invoke(self, payload, **kwargs):
        return {"result": payload["query"]}


honey = canari.init(db_path="/tmp/canari-langchain.db")
canary = honey.generate(n_tokens=1, token_types=["api_key"])[0]

chain = DummyChain()
safe_chain = honey.wrap_chain(chain)

safe_chain.invoke({"query": f"Leaked: {canary.value}"})
