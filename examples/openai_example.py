"""
Real OpenAI example with agsec protection.

Run: pip install agsec[openai] && export OPENAI_API_KEY=sk-...
     python examples/openai_example.py
"""

import json

from openai import OpenAI

from agsec.integrations.openai import protect, allow, deny, review, param

# Protect the client — one line
client = protect(
    OpenAI(),
    allow("get_weather", "search"),
    deny("delete_user"),
    deny("send_money").when(param("amount") > 1000),
    review("send_email"),
)

# Define tools the LLM can call
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather for a city",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_money",
            "description": "Send money to someone",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "amount": {"type": "number"},
                },
                "required": ["to", "amount"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_user",
            "description": "Delete a user account",
            "parameters": {
                "type": "object",
                "properties": {"user_id": {"type": "string"}},
                "required": ["user_id"],
            },
        },
    },
]

# Ask the LLM to do something
print("=== Test 1: Safe request (weather) ===")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "What's the weather in Tokyo?"}],
    tools=tools,
)

if response.choices[0].message.tool_calls:
    for tc in response.choices[0].message.tool_calls:
        print(f"  ALLOWED: {tc.function.name}({tc.function.arguments})")
else:
    print(f"  Response: {response.choices[0].message.content}")

# Check if anything was blocked
if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")


print("\n=== Test 2: Dangerous request (delete user) ===")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Delete user account abc123"}],
    tools=tools,
)

if response.choices[0].message.tool_calls:
    for tc in response.choices[0].message.tool_calls:
        print(f"  ALLOWED: {tc.function.name}({tc.function.arguments})")
else:
    print(f"  No tool calls (blocked or text response)")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")


print("\n=== Test 3: Conditional block (large payment) ===")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Send $50,000 to Bob"}],
    tools=tools,
)

if response.choices[0].message.tool_calls:
    for tc in response.choices[0].message.tool_calls:
        print(f"  ALLOWED: {tc.function.name}({tc.function.arguments})")
else:
    print(f"  No tool calls (blocked or text response)")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")
