"""
Real OpenRouter example with agsec protection.
Works with any model on OpenRouter (Llama, Mistral, Claude, GPT, etc.)

Run: pip install agsec[openai] && export OPENROUTER_API_KEY=sk-or-...
     python examples/openrouter_example.py
"""

import json
import os

from openai import OpenAI

from agsec.integrations.openai import protect, allow, deny, review, param

# OpenRouter uses the OpenAI SDK with a different base URL
client = protect(
    OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ.get("OPENROUTER_API_KEY"),
    ),
    allow("search_web", "get_stock_price"),
    deny("execute_code"),
    deny("transfer_funds").when(param("amount") > 5000),
    review("send_notification"),
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Search the web",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_code",
            "description": "Execute Python code",
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "transfer_funds",
            "description": "Transfer money",
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
]

# Use any model available on OpenRouter
response = client.chat.completions.create(
    model="minimax/minimax-m2.5:free",
    messages=[{"role": "user", "content": "Search for the latest AI security news"}],
    tools=tools,
)

print("=== OpenRouter + agsec ===")
if response.choices[0].message.tool_calls:
    for tc in response.choices[0].message.tool_calls:
        print(f"  ALLOWED: {tc.function.name}({tc.function.arguments})")
else:
    content = response.choices[0].message.content
    print(f"  Response: {content[:200] if content else '(no content)'}")

if hasattr(response, "_agsec_blocked") and response._agsec_blocked:
    for b in response._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']}")
