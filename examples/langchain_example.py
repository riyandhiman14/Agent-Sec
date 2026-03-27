"""
Real LangChain example with agsec protection.

Run: pip install agsec[langchain] langchain-openai
     export OPENAI_API_KEY=sk-...
     python examples/langchain_example.py
"""

from agsec.integrations.langchain import guard, allow, deny, review, param

# --- Step 1: Define your tools ---

try:
    from langchain_core.tools import tool

    @tool
    def search(query: str) -> str:
        """Search the web for information."""
        return f"Results for: {query}"

    @tool
    def calculator(expression: str) -> str:
        """Evaluate a math expression."""
        try:
            return str(eval(expression))  # noqa: S307
        except Exception as e:
            return f"Error: {e}"

    @tool
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to someone."""
        return f"Email sent to {to}: {subject}"

    @tool
    def delete_database(table: str) -> str:
        """Delete a database table."""
        return f"Deleted table: {table}"

    @tool
    def process_payment(amount: float, recipient: str) -> str:
        """Process a payment."""
        return f"Paid ${amount} to {recipient}"

    # --- Step 2: Protect tools with one line ---

    protected_tools = guard(
        allow(search, calculator),
        review(send_email),
        deny(delete_database),
        deny(process_payment).when(param("amount") > 10000),
    )

    print("=== agsec + LangChain ===\n")
    print(f"Protected {len(protected_tools)} tools:\n")
    for t in protected_tools:
        print(f"  {t.name}: {t.description}")

    # --- Step 3: Test each tool ---

    print("\n--- Testing tools ---\n")

    # search: ALLOWED
    try:
        result = search.invoke({"query": "python docs"})
        print(f"  search('python docs') -> {result}")
    except Exception as e:
        print(f"  search -> BLOCKED: {e}")

    # delete_database: BLOCKED by agsec
    print()
    from agsec.exceptions import PolicyViolationError

    try:
        # Use the protected version
        result = protected_tools[3].invoke({"table": "users"})
        print(f"  delete_database('users') -> {result}")
    except PolicyViolationError as e:
        print(f"  delete_database('users') -> BLOCKED: {e}")

    # process_payment small: ALLOWED
    try:
        result = protected_tools[4].invoke({"amount": 50.0, "recipient": "Bob"})
        print(f"  process_payment($50) -> {result}")
    except PolicyViolationError as e:
        print(f"  process_payment($50) -> BLOCKED: {e}")

    # process_payment large: BLOCKED
    try:
        result = protected_tools[4].invoke({"amount": 50000.0, "recipient": "Bob"})
        print(f"  process_payment($50000) -> {result}")
    except PolicyViolationError as e:
        print(f"  process_payment($50000) -> BLOCKED: {e}")

    # --- Step 4: Use with an agent (uncomment if you have langchain-openai) ---

    # from langchain_openai import ChatOpenAI
    # from langgraph.prebuilt import create_react_agent
    #
    # llm = ChatOpenAI(model="gpt-4o-mini")
    # agent = create_react_agent(llm, protected_tools)
    #
    # result = agent.invoke({"messages": [{"role": "user", "content": "What's 42 * 17?"}]})
    # print(result["messages"][-1].content)

except ImportError:
    print("Install langchain-core to run this example:")
    print("  pip install agsec[langchain]")
