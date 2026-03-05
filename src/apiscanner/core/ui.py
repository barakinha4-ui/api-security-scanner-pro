"""
core/ui.py — Terminal UI utilities for the API Security Scanner.
"""

class C:
    """ANSI Escape sequences for terminal colors."""
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def c(text: str, colour: str) -> str:
    """Helper to wrap text in ANSI colors."""
    return f"{colour}{text}{C.RESET}"
