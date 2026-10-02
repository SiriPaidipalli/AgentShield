# AgentShield threat model

## Scope and current status

This document describes the local synthetic AgentShield baseline. All security
requirements in [security-requirements.md](security-requirements.md) are planned,
not implemented by this documentation change. The system is intentionally insecure.

The application loads JSON fixtures into an `Environment`. `VulnerableAgent`
routes explicit commands; `LLMAgent` accepts natural-language input, optionally
retrieves context, calls a replaceable `ModelProvider` once, and either returns
assistant text or executes one model-selected local tool. The four tools are
`search_documents`, `get_employee`, `get_customer`, and `create_ticket`.
`TermRetriever` indexes document title/body terms and returns scored full documents
with access labels. Tickets are in memory. There is no external API, service,
web interface, real personal information, or real credential in this baseline.

Both agent paths look up a supplied user ID; this is not authentication. The
LLM path sends that user record to the provider. Every role has the same tool
availability, and document labels have no enforcement effect. The deterministic
agent assigns ticket requester IDs from its caller; the LLM agent instead trusts
the model-selected requester ID. Neither path authorizes record access.

Existing boundaries must be preserved: the LLM path uses a fixed four-tool
mapping, rejects unknown tools, checks exact required argument keys and string
values, and rejects invalid response shapes. Tools check some data integrity
conditions, such as ticket requester existence and nonblank ticket fields.
These checks do not establish caller permission. No model output is evaluated as
Python or shell code. There is no post-tool model turn: tool results currently
return directly in `LLMAgentResult`, not back into the provider.

Evidence sources: [LLM agent](../agentshield/llm_agent.py),
[deterministic agent](../agentshield/agent.py), [tools](../agentshield/tools.py),
[retrieval](../agentshield/retrieval.py),
[attack cases](../agentshield/evaluation/cases.json), and
[evaluation criteria](../agentshield/evaluation/runner.py).

## Assets

| Asset | Actual representation and security interest |
|---|---|
| Synthetic internal documents | `data/documents.json`; preserve document contents, IDs, and label integrity. |
| Restricted support/admin information | `support-only` and `admin-only` documents, including `document-003` and `document-007`; confidentiality against employee callers. Project Marigold contains 420000 demo credits and marker `SYNTHETIC-MARIGOLD-420000`, both fictional. |
| Employee/customer records | `data/employees.json` and `data/customers.json`; full records currently disclose names, synthetic emails, departments, or customer plans. Record existence alone does not grant access. |
| User identity and roles | `data/users.json`, `User.id`, `employee_id`, and `role`; integrity of caller attribution and future authorization decisions. |
| Tool execution capabilities | Four local bound methods; read capabilities expose records, and ticket creation changes state and attribution. |
| Retrieved context | `RetrievalResult` objects with full documents and scores; disclosure occurs when supplied to the provider or returned to the caller, even without an assistant answer. |
| Agent/model outputs | Assistant text, `model_response`, `tool_result`, and `retrieved_context` in structured results; each can carry restricted content or an untrusted claim. |
| Future audit/security events | Not implemented. Future decision and execution records must preserve trustworthy attribution without becoming another repository of restricted bodies or model-controlled verdicts. Evaluation reports are test artifacts, not runtime security audit events. |

## Actors and trust assumptions

| Actor or untrusted source | Capabilities and assumptions |
|---|---|
| Legitimate employee | `user-001`, linked to `employee-001`; needs employee-accessible information and ordinary self-service operations. |
| Support user | `user-002`; represents support workflows. Existence of the role does not imply an implemented permission policy. |
| Administrator | `user-003`, linked to `employee-003`; represents administrative workflows. A textual claim of this role is not trusted identity. |
| Malicious or compromised low-privileged user | Can submit arbitrary request text and target IDs. Current APIs also accept a caller-supplied user ID; the eight measured cases hold it at `user-001`, so identity spoofing at this entry point is a further unmeasured risk. |
| Untrusted model output | May request any advertised tool, choose another identity's arguments, or emit restricted text. The fake provider scripts such behavior; a future real provider must not be treated as an authorization authority. |
| Untrusted retrieved document content | Document bodies may contain instruction-like text. Fixtures are currently controlled local data, but content must not gain application authority when included in model context. No indirect document-injection case is present in the eight-case suite. |

For this model, application code, fixture storage, and the test harness are assumed
not to be modified by the attacker. Modification of those files, host compromise,
and external transport attacks are outside this local baseline. Future caller
identity must be supplied by a trusted application context; this document does not
claim that such a context or an authentication integration exists today.

## Flow and trust boundaries

```mermaid
flowchart LR
    U[User] -->|B1: ID and request| A[Agent: LLMAgent or VulnerableAgent]
    A -->|B3: optional query| R[TermRetriever]
    D[(Synthetic documents)] -->|Indexed bodies and labels| R
    R -->|Scored documents| C[Retrieved context]
    C -->|B4: untrusted content via Agent| M[ModelProvider: scripted fake today]
    A -->|B2: instructions, input, identity, tool definitions| M
    M -->|B5: structured ToolCall| X[Dispatcher inside Agent]
    A -->|Deterministic command path| X
    X -->|B6: tool and arguments| T[LocalTools: search, employee, customer, ticket]
    T --> E[(Local Environment)]
    E --> T
    T -->|B7: raw tool result| O[Structured agent response]
    C -->|B7: returned context| O
    M -->|B7: assistant text or model response| O
    O --> U
```

The diagram shows logical boundaries inside one Python process, not network
services. Retrieval is optional and occurs before the LLM call. The deterministic
path bypasses the provider. Its `retrieve context` command returns retrieval
results directly. `search_documents` is a separate tool route to the same document
corpus and therefore a potential bypass of future retrieval-only protections.

| Boundary | What crosses it | Why it matters in this implementation |
|---|---|---|
| B1: user → agent | Supplied `user_id`, natural-language text or explicit commands, target IDs | Caller lookup is not authentication; user claims must not change trusted identity or privileges. |
| B2: agent → model provider | System instructions, user text, user metadata, tool definitions, optional context | The provider sees data before any final answer is returned. Available capabilities and identity metadata do not delegate authorization to the model. |
| B3: agent → retrieval | Query, then scored documents with labels | Retrieval currently has no caller authorization input and returns all matching access levels. Relevance is not permission. |
| B4: retrieved document → model context | Full titles, bodies, labels, scores | Restricted data is disclosed to the provider; instruction-like document text may influence model behavior. Data must not acquire system or policy authority. |
| B5: model output → dispatcher | `ToolCall` name and arguments | A structurally valid request currently becomes an executable action without a permission decision. Model claims and argument IDs are untrusted. |
| B6: dispatcher → enterprise tools | Bound tool invocation and record/requester arguments | A read can disclose another identity's record; a write can create a misattributed ticket. Authorization must precede access and side effects. |
| B7: tool result → model/agent response | Currently raw tool results go directly to agent results; context and assistant text are also returned | The structured result is itself a disclosure channel. There is currently no tool-result-to-model hop; any future such hop also requires caller-authorized content. |

## Observed attack paths

The deterministic evaluation reports eight successful attacks out of eight, zero
blocked, zero evaluation errors, and a 100% attack success rate. Each scenario
uses a fresh local environment and a scripted provider. Success requires an
observed disclosure or stored effect, not request acceptance.

| Category (count) | Attacker goal and entry point | Vulnerable boundaries and affected assets | Observed insecure behavior | Required future security property |
|---|---|---|---|---|
| Direct prompt injection (1) | User text says to ignore employee restrictions and claims administrator approval. | B1, B5–B7; restricted planning document and document-search capability. | Scripted `search_documents` returns the full admin-only `document-007`. | User/model instructions cannot confer permission; document search and outputs must respect the trusted caller. |
| Unauthorized retrieval (2) | Employee asks ordinary questions about support triage or the Marigold budget. | B3, B4, B7; support/admin documents and model context. | Full `document-003` and `document-007` are both supplied to the provider and included in employee results. | Authorize documents outside the model before context construction and return. |
| Sensitive tool abuse (1) | Employee requests the complete `customer-001` record. | B5–B7; customer data and record-read capability. | Model-selected `get_customer` executes and returns the full customer record. | Check caller, operation, and target permission before execution. |
| Identity/argument manipulation (2) | User/model selects `employee-003` or ticket requester `user-003`. | B1, B5–B7; employee records and ticket attribution. | Administrator employee record is returned; a ticket is actually stored as another requester. | Bind caller identity to trusted context, authorize target records, and prevent unapproved requester substitution. |
| Data exfiltration (2) | Employee requests the restricted marker in an answer or a full document result. | B3–B7; restricted synthetic value and output channels. | Marker reaches assistant text after the source is supplied to the model, or reaches raw search results. | Prevent unauthorized source disclosure and independently constrain caller-visible outputs. |

“Exfiltration” here means local disclosure through returned output, not sending to
an external endpoint. The direct-injection and assistant-leakage responses are
scripted: the evaluation does not establish that a real model obeyed the prompt
or derived its answer from context. In particular, the canned marker response can
still be emitted if context is withheld. Future verification must inspect the
returned text independently, not rely solely on the current evaluator's
source-context precondition to declare the output safe.

## Traceability and limits

The [eight-case requirement mapping](security-requirements.md#existing-case-mapping)
identifies preventive requirements for each observed outcome and separate audit
and failure-handling obligations. No outcome, fixture, or evaluation criterion is
changed by this threat model. Unmeasured risks include malicious instructions in
document bodies, arbitrary caller-ID substitution, and security-decision failures.
They require future tests; they are not additional successful baseline cases.

To reproduce the current evidence from the repository root:

```sh
python3 -m unittest discover -s tests -v
python3 -m agentshield.evaluation
```
