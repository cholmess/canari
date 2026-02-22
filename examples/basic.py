import canari

honey = canari.init(db_path="/tmp/canari-example.db")
canaries = honey.generate(n_tokens=2, token_types=["api_key", "email"])

prompt = honey.inject_system_prompt("You are a helpful assistant.", canaries=canaries)
print(prompt)

sample_output = f"Leaked value: {canaries[0].value}"
alerts = honey.scan_output(sample_output, context={"conversation_id": "demo-conv"})
print(f"alerts={len(alerts)}")
