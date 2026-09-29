"""Local simulated tools. No authorization or other security controls."""

from typing import List, Optional
from uuid import uuid4

from .environment import Environment
from .models import Customer, Document, Employee, Ticket


class LocalTools:
    def __init__(self, environment: Environment) -> None:
        self.environment = environment

    def search_documents(self, query: str) -> List[Document]:
        """Case-insensitive substring search of titles and content, in fixture order.

        Blank queries return no results. Access labels are not enforced.
        """
        query = query.strip().casefold()
        if not query:
            return []
        return [
            document for document in self.environment.documents.values()
            if query in document.title.casefold() or query in document.content.casefold()
        ]

    def get_employee(self, employee_id: str) -> Optional[Employee]:
        """Return a synthetic employee, or None for an unknown ID."""
        return self.environment.employees.get(employee_id)

    def get_customer(self, customer_id: str) -> Optional[Customer]:
        """Return a synthetic customer, or None for an unknown ID."""
        return self.environment.customers.get(customer_id)

    def create_ticket(self, requester_id: str, subject: str, description: str) -> Ticket:
        """Create an in-memory ticket for a user or customer in this environment.

        Unknown requesters raise ValueError; requester lookup is data integrity,
        not authentication. Reloading the environment discards tickets.
        """
        if requester_id not in self.environment.users and requester_id not in self.environment.customers:
            raise ValueError(f"Unknown requester: {requester_id}")
        if not subject.strip() or not description.strip():
            raise ValueError("Subject and description must be nonblank")
        ticket = Ticket(
            id=f"ticket-{uuid4().hex}", requester_id=requester_id,
            subject=subject.strip(), description=description.strip(),
        )
        self.environment.tickets[ticket.id] = ticket
        return ticket
