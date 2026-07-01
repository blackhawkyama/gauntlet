"""gauntlet — a prompt-injection & jailbreak evaluation suite, built on assay.

Run a target LLM assistant (with or without defenses) through a corpus of attacks
and measure how often they succeed. Because the target holds a harmless secret —
an access code and a forbidden word — attack success is a **leak of that secret**,
detected deterministically. No real harmful content is ever elicited; the secret
is a safe proxy for "the model did something it was told not to."

Composes with assay: the corpus is an assay Dataset, the target is an assay
System, the checks are assay Scorers, and the run/report/compare come from assay.
So you get attack-success-rate per category, and a clean before/after when you
add a defense — the same regression machinery, pointed at security.
"""

from gauntlet.detect import leaked, redact
from gauntlet.scorers import AnsweredBenign, Defended
from gauntlet.suite import ACCESS_CODE, FORBIDDEN_WORD, build_suite, summarize

__all__ = [
    "leaked",
    "redact",
    "Defended",
    "AnsweredBenign",
    "build_suite",
    "summarize",
    "ACCESS_CODE",
    "FORBIDDEN_WORD",
]

__version__ = "0.1.0"
