#!/usr/bin/env python3
"""
SecurePass — Privacy-First Password Strength Checker
Cybersecurity Internship Project: Task 1

Evaluates password strength locally using Shannon entropy,
brute-force search space models, common wordlists, and pattern heuristics.
ZERO STORAGE, ZERO TELEMETRY, ZERO TRANSMISSION.
"""
import argparse
import getpass
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from checker import analyze

COLORS = {
    "Very Weak": "\033[91m",
    "Weak": "\033[91m",
    "Moderate": "\033[93m",
    "Strong": "\033[92m",
    "Very Strong": "\033[96m"
}
RESET = "\033[0m"


def render(a, color: bool) -> str:
    c = COLORS.get(a.rating, "") if color else ""
    r = RESET if color else ""
    filled = round(a.score / 5)
    bar = "#" * filled + "-" * (20 - filled)
    lines = [
        "",
        "============================================================",
        "  SecurePass — Local Password Strength Analysis (Offline)",
        "============================================================",
        f"Strength : {c}{a.rating}{r}  [{c}{bar}{r}] {a.score}/100",
        f"Length   : {a.length} characters (Pool size: {a.pool_size})",
        f"Entropy  : Pool {a.pool_entropy:.1f} bits | Shannon {a.shannon_entropy:.1f} bits ({a.shannon_per_char:.2f} bits/char)",
        f"Final    : {a.final_bits:.1f} effective bits after penalty deduction",
        f"Est. offline crack time: {a.crack_time}",
    ]
    if a.findings:
        lines += ["", "Vulnerabilities Detected:"] + [f"  - {f.detail}" for f in a.findings]
    if a.suggestions:
        lines += ["", "Defensive Security Recommendations:"] + [f"  * {s}" for s in a.suggestions]
    lines.append("============================================================\n")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="SecurePass: Privacy-First Password Strength Checker (Offline)."
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    args = parser.parse_args(argv)

    try:
        pw = getpass.getpass("Enter password (hidden, zero echo, never stored or transmitted): ")
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled.")
        return 1

    result = analyze(pw)
    del pw  # Immediately clear password reference from memory
    print(render(result, color=sys.stdout.isatty() and not args.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
