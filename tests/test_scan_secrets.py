"""Secret scanner: unit tests, plus an end-to-end check that the git hook
really blocks a commit.

Fake secrets are assembled at runtime so this file itself never contains
anything key-shaped (otherwise the scanner would block committing it).
"""

import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "scripts" / "scan_secrets.py"
HOOK = ROOT / ".githooks" / "pre-commit"

spec = importlib.util.spec_from_file_location("scan_secrets", SCANNER)
scan_secrets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_secrets)

FAKE_GOOGLE_KEY = "AIza" + "A1b2C3d4E5" * 3 + "F6g7H"  # 4 + 35 chars, the key shape
FAKE_PRIVATE_KEY = "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize("name", [".env", ".env.local", "config/.env.prod", "server.pem",
                                  "id.key", "credentials.json", "service-account-prod.json"])
def test_blocked_filenames(name):
    assert scan_secrets.is_blocked_filename(name)


@pytest.mark.parametrize("name", [".env.example", "README.md", "triage_agents/config.py",
                                  "data/environment.json"])
def test_allowed_filenames(name):
    assert not scan_secrets.is_blocked_filename(name)


def test_detects_google_api_key():
    assert scan_secrets.find_secrets(f"GOOGLE_API_KEY={FAKE_GOOGLE_KEY}") == ["Google API key"]


def test_detects_private_key_block():
    assert scan_secrets.find_secrets(FAKE_PRIVATE_KEY) == ["private key block"]


def test_ignores_normal_text():
    assert scan_secrets.find_secrets("GOOGLE_API_KEY=") == []
    assert scan_secrets.find_secrets("AIza is how Google keys start") == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_hook_blocks_a_real_commit(tmp_path):
    """Make a throwaway repo with our hook, try to commit a fake key, expect failure."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / ".githooks").mkdir()
    shutil.copy(SCANNER, tmp_path / "scripts" / "scan_secrets.py")
    shutil.copy(HOOK, tmp_path / ".githooks" / "pre-commit")

    def git(*args):
        return subprocess.run(
            ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
            cwd=tmp_path, capture_output=True, text=True)

    git("init", "-q")
    git("config", "core.hooksPath", ".githooks")

    (tmp_path / "settings.py").write_text(f'KEY = "{FAKE_GOOGLE_KEY}"\n')
    git("add", "settings.py")
    blocked = git("commit", "-q", "-m", "should be blocked")
    assert blocked.returncode != 0
    assert "Google API key" in blocked.stderr
    assert FAKE_GOOGLE_KEY not in blocked.stderr  # the value is masked

    (tmp_path / "settings.py").write_text('KEY = os.environ["GOOGLE_API_KEY"]\n')
    git("add", "settings.py")
    allowed = git("commit", "-q", "-m", "clean commit")
    assert allowed.returncode == 0, allowed.stderr
