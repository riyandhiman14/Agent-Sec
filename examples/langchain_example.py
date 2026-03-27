"""
agsec + LangChain — protect agent tools with inline policies.

Install: pip install agsec[langchain] langchain-core
"""

from agsec.integrations.langchain import guard, allow, deny, review, param

# --- Assume these are your LangChain tools ---
# from langchain_core.tools import tool
#
# @tool
# def search(query: str) -> str:
#     """Search the web."""
#     return f"Results for: {query}"
#
# @tool
# def send_email(to: str, subject: str, body: str) -> str:
#     """Send an email."""
#     return f"Email sent to {to}"
#
# @tool
# def payment(amount: float, recipient: str) -> str:
#     """Process a payment."""
#     return f"Charged {amount} to {recipient}"
#
# @tool
# def delete_record(table: str, id: int) -> str:
#     """Delete a database record."""
#     return f"Deleted {id} from {table}"

# --- Protect your tools with one line ---

# protected_tools = guard(
#     allow(search),                                    # search is always fine
#     review(send_email),                               # emails need human approval
#     deny(delete_record),                              # never let the agent delete
#     deny(payment).when(param("amount") > 10000),      # block large payments
# )

# --- Pass to your agent ---

# from langgraph.prebuilt import create_react_agent
# agent = create_react_agent(llm, protected_tools)

# --- What happens ---
# agent calls search("python docs")         -> ALLOWED
# agent calls send_email(...)               -> BLOCKED (review required)
# agent calls delete_record(...)            -> BLOCKED
# agent calls payment(amount=500)           -> ALLOWED
# agent calls payment(amount=50000)         -> BLOCKED (amount > 10000)

print("""
agsec LangChain integration example.

Usage:
  from agsec.integrations.langchain import guard, allow, deny, review, param

  protected_tools = guard(
      allow(search, calculator),
      review(send_email),
      deny(delete_record),
      deny(payment).when(param("amount") > 10000),
  )

  agent = create_react_agent(llm, protected_tools)

Install langchain-core to run this example:
  pip install agsec[langchain] langchain-core
""")
