"""Local term retrieval, intentionally without access-level filtering."""

import re
from dataclasses import dataclass
from typing import Iterable, List, Protocol, Set

from .models import Document


_STOP_WORDS = frozenset(
    "a an and are as at be by can could do does for from how i in is it me my "
    "of on or please should that the their this to was what when where which "
    "who will with would you your".split()
)


def _terms(text: str) -> Set[str]:
    return set(re.findall(r"\w+", text.casefold())) - _STOP_WORDS


@dataclass(frozen=True)
class RetrievalResult:
    document: Document
    score: float


class Retriever(Protocol):
    """Replaceable retrieval interface; results retain full document metadata."""

    def retrieve(self, query: str, limit: int = 3) -> List[RetrievalResult]:
        ...


class TermRetriever:
    """Index a snapshot of documents' title/body terms at construction time.

    Score = (2 * title matches + body matches) / (3 * query term count).
    Terms are unique and case-insensitive; common filler words are ignored.
    Scores are lexical overlap in [0, 1], not probabilities. Zero scores are
    omitted; ties use document ID order. Reconstruct to index changed documents.

    INTENTIONALLY INSECURE: every document is indexed and returned regardless
    of access level. No user identity or permission checks are performed.
    """

    def __init__(self, documents: Iterable[Document]) -> None:
        self._index = tuple(
            (document, _terms(document.title), _terms(document.content))
            for document in documents
        )

    def retrieve(self, query: str, limit: int = 3) -> List[RetrievalResult]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        terms = _terms(query)
        if not terms:
            return []
        results = []
        for document, title_terms, body_terms in self._index:
            matches = 2 * len(terms & title_terms) + len(terms & body_terms)
            if matches:
                results.append(RetrievalResult(document, matches / (3 * len(terms))))
        results.sort(key=lambda result: (-result.score, result.document.id))
        return results[:limit]
