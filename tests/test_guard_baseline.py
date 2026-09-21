from pathlib import Path
import json
import subprocess

from inginv.repo_guard import scan_repository


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout.strip()


def test_baseline_is_pinned_to_exact_blob_and_invalidates_on_change(tmp_path: Path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "Test")

    key = "pass" + "word"
    tracked = tmp_path / "config.txt"
    tracked.write_text(key + "=" + ("7" * 6) + "\n", encoding="utf-8")
    _git(tmp_path, "add", "config.txt")
    _git(tmp_path, "commit", "-qm", "fixture")
    blob = _git(tmp_path, "rev-parse", "HEAD:config.txt")

    baseline_dir = tmp_path / ".inginv"
    baseline_dir.mkdir()
    baseline = {
        "version": 1,
        "entries": [
            {
                "path": "config.txt",
                "blob": blob,
                "rule": "HARDCODED_CREDENTIAL",
                "line": 1,
            }
        ],
    }
    baseline_path = baseline_dir / "guard-baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    _git(tmp_path, "add", ".inginv/guard-baseline.json")
    _git(tmp_path, "commit", "-qm", "baseline")

    report = scan_repository(tmp_path)
    assert report["blocking_count"] == 0
    assert report["baselined_count"] == 1

    # Same path and line, different bytes: the previous approval must not carry.
    tracked.write_text(key + "=" + ("8" * 6) + "\n", encoding="utf-8")
    changed = scan_repository(tmp_path)
    assert changed["blocking_count"] == 1
    assert changed["baselined_count"] == 0
