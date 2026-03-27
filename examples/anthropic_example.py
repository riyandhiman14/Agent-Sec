"""
Real Anthropic example with agsec protection.

Run: pip install agsec[anthropic] && export ANTHROPIC_API_KEY=sk-ant-...
     python examples/anthropic_example.py
"""

import json

from anthropic import Anthropic

from agsec.integrations.anthropic import protect, allow, deny, review, param

# Protect the client — one line
client = protect(
    Anthropic(),
    allow("get_weather", "search"),
    deny("delete_user"),
    deny("run_sql").when(param("query").contains("DROP")),
    review("send_email"),
)

# Define tools
tools = [
    {
        "name": "get_weather",
        "description": "Get weather for a city",
        "input_schema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
    {
        "name": "delete_user",
        "description": "Delete a user account",
        "input_schema": {
            "type": "object",
            "properties": {"user_id": {"type": "string"}},
            "required": ["user_id"],
        },
    },
    {
        "name": "run_sql",
        "description": "Run a SQL query",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
]

print("=== Test 1: Safe request (weather) ===")
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "What's the weather in Paris?"}],
    tools=tools,
)

for block in response.content:
    if block.type == "tool_use":
        print(f"  ALLOWED: {block.name}({json.dumps(block.input)})")
    elif block.type == "text":
        print(f"  Text: {block.text}")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")


print("\n=== Test 2: Dangerous request (delete user) ===")
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Delete user xyz789 from the system"}],
    tools=tools,
)

for block in response.content:
    if block.type == "tool_use":
        print(f"  ALLOWED: {block.name}({json.dumps(block.input)})")
    elif block.type == "text":
        print(f"  Text: {block.text}")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")


print("\n=== Test 3: Conditional block (SQL injection) ===")
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Run this query: DROP TABLE users"}],
    tools=tools,
)

for block in response.content:
    if block.type == "tool_use":
        print(f"  ALLOWED: {block.name}({json.dumps(block.input)})")
    elif block.type == "text":
        print(f"  Text: {block.text}")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")
