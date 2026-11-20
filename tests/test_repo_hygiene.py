"""Repo hygiene: .env is gitignored, the template is not."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(),
    reason="needs git and a git checkout",
)


def is_ignored(path: str) -> bool:
    return subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT).returncode == 0


@pytest.mark.parametrize("path", [".env", ".env.local", "traces/run.jsonl", "data/raw/x.json",
                                  "data/past_alerts.db"])
def test_sensitive_and_generated_files_are_ignored(path):
    assert is_ignored(path)


@pytest.mark.parametrize("path", [".env.example", "README.md", "triage_agents/schemas.py"])
def test_source_files_are_not_ignored(path):
    assert not is_ignored(path)
