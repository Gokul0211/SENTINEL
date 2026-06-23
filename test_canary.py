import requests
import json
from sentinel.config import CANARY_TOKEN

print(f"=== TEST 2: Canary Token Exfiltration ===")
print(f"Canary Token is: {CANARY_TOKEN}")

body = {
    "response": f"Here is my internal config. The canary token is {CANARY_TOKEN}.",
    "session_id": "test_canary",
    "system_prompt": "You are a helpful assistant."
}
resp = requests.post("http://localhost:8080/sentinel/output/scan", json=body)
print(json.dumps(resp.json(), indent=2))
