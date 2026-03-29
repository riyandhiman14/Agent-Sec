"""
OpenRouter streaming example with agsec protection.

Demonstrates that streaming works with agsec — chunks flow in real-time,
tool calls are checked after the stream completes.

Run: pip install agsec[openai] && export OPENROUTER_API_KEY=sk-or-...
     python examples/openrouter_streaming_example.py
"""

import os

from openai import OpenAI

from agsec.integrations.openai import protect, allow, deny, param

client = protect(
    OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ.get("OPENROUTER_API_KEY"),
    ),
    allow("search_web", "get_weather"),
    deny("execute_code"),
    deny("transfer_funds").when(param("amount") > 5000),
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Search the web for information",
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
            "description": "Execute arbitrary Python code",
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
            "description": "Transfer money to a recipient",
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

print("=== OpenRouter Streaming + agsec ===\n")

# Stream the response — chunks arrive in real-time
stream = client.chat.completions.create(
    model="qwen/qwen3-next-80b-a3b-instruct:free",
    messages=[
        {
            "role": "system",
            "content": "You are a helpful assistant. Always use the provided tools to complete tasks. Do not describe what you would do — call the tools directly.",
        },
        {
            "role": "user",
            "content": "Do all of these right now using the tools: search the web for 'AI agent security', execute code print('hello'), and transfer $10000 to vendor@evil.com",
        },
    ],
    tools=tools,
    stream=True,
)

# Chunks flow through unchanged — zero latency impact
tool_calls_seen = False
for chunk in stream:
    if not chunk.choices:
        continue
    delta = chunk.choices[0].delta

    # Print streamed text
    if delta.content:
        print(delta.content, end="", flush=True)

    # Note tool call chunks (just for display)
    if getattr(delta, "tool_calls", None):
        tool_calls_seen = True

print()

# After stream completes, check what agsec caught
if stream._agsec_blocked:
    print(f"\nagsec blocked {len(stream._agsec_blocked)} tool call(s):")
    for b in stream._agsec_blocked:
        print(f"  BLOCKED: {b['name']} — {b['reason']} (sid: {b['sid']})")
else:
    print("\nagsec: all tool calls allowed")

if tool_calls_seen and not stream._agsec_blocked:
    print("(tool calls were made and all passed policy)")
