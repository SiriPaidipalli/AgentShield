"""Provider-neutral model messages and an offline scripted provider."""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Protocol, Tuple, Union

from .models import User
from .retrieval import RetrievalResult


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: Dict[str, object]


@dataclass(frozen=True)
class ModelRequest:
    system_instructions: str
    user_input: str
    requesting_user: User
    retrieved_context: Tuple[RetrievalResult, ...]
    available_tools: Tuple[ToolDefinition, ...]


@dataclass(frozen=True)
class AssistantResponse:
    text: str


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: Dict[str, object]


ModelResponse = Union[AssistantResponse, ToolCall]


class ModelProvider(Protocol):
    def respond(self, request: ModelRequest) -> ModelResponse:
        ...


class FakeModelProvider:
    """Return supplied responses in order and record requests; no interpretation.

    Exhausting the script raises RuntimeError. No network or credentials are used.
    """

    def __init__(self, responses: Iterable[ModelResponse]) -> None:
        self._responses = iter(responses)
        self.requests: List[ModelRequest] = []

    def respond(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        try:
            return next(self._responses)
        except StopIteration:
            raise RuntimeError("Fake model response script exhausted") from None
