# AgentShield
Security testing and runtime protection for LLM agents, RAG pipelines, and tool-driven workflows.

## Synthetic foundation

The current implementation uses Python 3.8+ and only the standard library.
All users, employees, customers, and documents are fictional local fixtures;
email addresses use `example.invalid`.

- `agentshield/models.py`: typed records, roles, and document access labels.
- `agentshield/environment.py`: configuration and JSON loading into independent environments.
- `agentshield/tools.py`: document substring search, employee/customer lookup, and ticket creation.
- `data/`: synthetic JSON fixtures.
- `tests/`: standard-library unit tests.

```python
from agentshield import LocalTools, load_environment

tools = LocalTools(load_environment())
documents = tools.search_documents("support")
employee = tools.get_employee("employee-001")
customer = tools.get_customer("customer-001")
ticket = tools.create_ticket("user-001", "Demo equipment request", "A fictional monitor is needed.")
```

`EnvironmentConfig(data_dir=Path("/path/to/fixtures"))` selects an alternative
local fixture directory (import `Path` from `pathlib`). The default data path is
relative to the source tree, independent of the working directory.
Tickets are stored only in the loaded environment's memory and reset on reload.
Unknown employee/customer IDs return `None`; blank searches return an empty list.
Ticket requesters must be existing user or customer IDs.
Roles and access levels are metadata only and are not enforced. No LLM, RAG,
external API, attacks, security controls, or evaluation logic is implemented.

Run all tests from this repository directory:

```sh
python3 -m unittest discover -s tests -v
```

## Intentionally vulnerable agent baseline

`agentshield/agent.py` adds `VulnerableAgent` and structured `AgentResult` records.
The separate deterministic parser accepts these case-insensitive command forms:

- `search documents <query>` → `search_documents`
- `get employee <id>` → `get_employee`
- `get customer <id>` → `get_customer`
- `create ticket <subject> | <description>` → `create_ticket`

Ticket creation uses the requesting user's ID; the first `|` separates the fields.
Malformed requests and unknown user IDs raise `ValueError`. User lookup only
provides metadata; it does not authenticate the caller. Tool errors propagate.

```python
from agentshield import LocalTools, VulnerableAgent, load_environment

agent = VulnerableAgent(LocalTools(load_environment()))
result = agent.handle_request("user-001", "search documents Admin Maintenance")
# Intentionally insecure: an employee receives the full admin-only document.
print(result.requesting_user.role, result.tool_result)
result = agent.handle_request("user-001", "get employee employee-003")
# Intentionally insecure: an employee receives the admin employee's full record.
print(result.tool_result)
```

Results include `requesting_user`, `action`, `tool_invoked`, and `tool_result`.
Every role can invoke every tool and receive unfiltered results. Access labels
remain unchanged. `tests/test_agent.py` explicitly tests these intentional
insecure behaviors alongside normal functionality. Routing uses no LLM or RAG.
