# AIA Python SDK

Official Python client for the Agent Identity and Capability Protocol (AICP).

## Installation

```bash
pip install aia-sdk
```

## Quick Start

```python
from aia_sdk import AIAClient

client = AIAClient(
    base_url="https://api.sealroot.com",
    api_key="your-api-key"
)

# 1. Register an agent
agent = client.register_agent(
    agent_name="my-agent",
    validity_hours=24
)
print(f"Agent ID: {agent['agent_id']}")
# IMPORTANT: Store agent['private_key'] securely — it won't be shown again

# 2. Issue a capability token
cap = client.issue_capability(
    agent_id=agent["agent_id"],
    capability_name="data:read",
    parameters={"table": "orders"},
    validity_seconds=3600
)

# 3. Generate a Signed Intent Envelope
sie = client.generate_sie(
    agent_certificate=agent["certificate"],
    private_key=agent["private_key"],
    capability_token=cap["token"],
    intent={
        "capability": "data:read",
        "parameters": {"table": "orders"}
    }
)

# 4. Verify the SIE
result = client.verify(sie=sie)
print(f"Result: {result['result']}")  # "allow" or "deny"
```

## Requirements

- Python 3.11+
- `httpx` for HTTP client
- `pynacl` for Ed25519 cryptography

## License

Apache License 2.0
