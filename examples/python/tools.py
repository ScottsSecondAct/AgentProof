"""Mock CRM tool implementations for the Customer Data Assistant example.

In production these would call a real database / email service. Here they
return static data so the example runs without external dependencies.
"""

from langchain.tools import tool


@tool
def get_customer_profile(account_id: str) -> dict:
    """Retrieve a customer record by account ID."""
    record = {
        "account_id": account_id,
        "name": "Jane Smith",
        "email": "jane.smith@example.com",
        "payment_method": "Visa ending 4242",
        "classification": "PII",
        "open_tickets": 3,
    }
    print(f"  [tool] get_customer_profile({account_id})")
    return record


@tool
def query_tickets(region: str, quarter: str) -> list:
    """Return open support ticket counts for a region and quarter."""
    data = [{"region": region, "quarter": quarter, "open_tickets": 42}]
    print(f"  [tool] query_tickets({region}, {quarter})")
    return data


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to the specified address."""
    print(f"  [tool] send_email(to={to!r}, subject={subject!r})")
    return f"Email sent to {to}"


@tool
def delete_record(account_id: str) -> str:
    """Delete a customer record. Requires prior human approval."""
    print(f"  [tool] delete_record({account_id})")
    return f"Record {account_id} deleted"


@tool
def human_approved(operation: str) -> str:
    """Record that a human operator has approved the next operation."""
    print(f"  [tool] human_approved(operation={operation!r})")
    return f"Human approval recorded for: {operation}"
