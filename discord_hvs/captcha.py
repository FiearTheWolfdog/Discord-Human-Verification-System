"""Utility helpers for generating and validating captcha challenges."""
from __future__ import annotations

import random
import string


# Exclude characters that are easily confused (e.g., O vs 0, I vs 1)
AMBIGUOUS = {"0", "O", "I", "1", "L"}
ALPHABET = "".join(ch for ch in (string.ascii_uppercase + string.digits) if ch not in AMBIGUOUS)


def generate_code(length: int = 6) -> str:
    """Return a random alphanumeric captcha code."""
    length = max(4, min(length, 12))
    return "".join(random.choice(ALPHABET) for _ in range(length))
