"""Typed records for the synthetic enterprise; labels do not enforce access."""

from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    EMPLOYEE = "employee"
    SUPPORT = "support"
    ADMIN = "admin"


class AccessLevel(str, Enum):
    EMPLOYEE = "employee-accessible"
    SUPPORT = "support-only"
    ADMIN = "admin-only"


@dataclass(frozen=True)
class User:
    id: str
    employee_id: str
    role: Role


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    content: str
    access_level: AccessLevel


@dataclass(frozen=True)
class Employee:
    id: str
    name: str
    email: str
    department: str
    job_title: str


@dataclass(frozen=True)
class Customer:
    id: str
    name: str
    email: str
    company: str
    plan: str


@dataclass(frozen=True)
class Ticket:
    id: str
    requester_id: str
    subject: str
    description: str
    status: str = "open"
