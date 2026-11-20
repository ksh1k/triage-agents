"""Block commits that contain secrets.

Run by the git pre-commit hook in .githooks/pre-commit. It checks two things in
the files you are about to commit:

1. File names: .env files (except .env.example), private keys, credential JSONs.
2. Added lines: text that looks like a Google API key, a private-key block,
   or a Google Cloud service-account file.

Matches are reported by file and line, with the secret itself masked.
Uses only the standard library, so it runs without the project's venv.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from pathlib import PurePosixPath

BLOCKED_FILENAME_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "credentials.json",
    "service-account*.json",
]
ALLOWED_FILENAMES = {".env.example"}

SECRET_PATTERNS = {
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "service-account JSON": re.compile(r'"type"\s*:\s*"service_account"'),
}


def is_blocked_filename(path: str) -> bool:
    """Return True if this file should never be committed, based on its name."""
    name = PurePosixPath(path).name
    if name in ALLOWED_FILENAMES:
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in BLOCKED_FILENAME_PATTERNS)


def find_secrets(text: str) -> list[str]:
    """Return the names of the secret patterns found in `text`."""
    return [label for label, pattern in SECRET_PATTERNS.items() if pattern.search(text)]


def _git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", check=True)
    return result.stdout


def scan_staged() -> list[str]:
    """Scan the staged changes and return one human-readable problem per finding."""
    problems: list[str] = []

    staged = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
    for path in staged:
        if is_blocked_filename(path):
            problems.append(f"{path}: this kind of file must not be committed")

    # -U0 shows only the changed lines; '+' lines are additions.
    current_file = None
    line_no = 0
    for line in _git("diff", "--cached", "-U0", "--no-color").splitlines():
        if line.startswith("+++ "):
            current_file = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            # Hunk header looks like: @@ -10,0 +11,3 @@
            match = re.search(r"\+(\d+)", line)
            line_no = int(match.group(1)) if match else 0
        elif line.startswith("+") and current_file:
            for label in find_secrets(line[1:]):
                problems.append(f"{current_file}:{line_no}: looks like a {label} (value hidden)")
            line_no += 1
    return problems


def main(argv: list[str]) -> int:
    if "--staged" not in argv:
        print("usage: python scripts/scan_secrets.py --staged", file=sys.stderr)
        return 2
    problems = scan_staged()
    if problems:
        print("Commit blocked by the secret scanner:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("Remove the secret (keep keys in .env), then try again.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
