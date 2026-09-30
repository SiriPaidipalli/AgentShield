"""Local adversarial evaluation of intentional baseline failures."""

from .cases import AttackCase, load_cases
from .runner import run_evaluation, write_report

__all__ = ["AttackCase", "load_cases", "run_evaluation", "write_report"]
