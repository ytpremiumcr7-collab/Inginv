from pathlib import Path
import subprocess

from inginv.repo_guard import scan_paths, scan_repository, scan_text


def test_detects_private_key_without_reproducing_key_material():
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    findings = scan_text("bad.txt", marker + "\ncontents")
    assert findings[0].rule == "PRIVATE_KEY"
    assert findings[0].evidence == "<PRIVATE_KEY_MATERIAL_REDACTED>"


def test_detects_rsa_private_key_header():
    marker = "-----BEGIN " + "RSA PRIVATE KEY-----"
    findings = scan_text("bad.txt", marker + "\ncontents")
    assert any(f.rule == "PRIVATE_KEY" for f in findings)


def test_detects_hardcoded_short_password_and_redacts_value():
    candidate = "654321"
    sample = ("pass" + "word") + "=" + candidate
    findings = scan_text("cfg.py", sample)
    assert findings[0].rule == "HARDCODED_CREDENTIAL"
    assert candidate not in findings[0].evidence


def test_ignores_explicit_example_secret():
    sample = ("pass" + "word") + "=example-not-a-real-secret"
    findings = scan_text("example.py", sample)
    assert not findings


def test_detects_device_identity_material():
    serial_line = "ro." + "serialno=ABC123456789"
    ssid_line = "SS" + 'ID="PrivateWifi"'
    findings = scan_text("dump.txt", serial_line + "\n" + ssid_line)
    rules = {f.rule for f in findings}
    assert {"DEVICE_SERIAL", "WIFI_SSID"} <= rules


def test_forbids_screenshot_artifacts(tmp_path: Path):
    screenshot = tmp_path / "screen.png"
    screenshot.write_bytes(b"not-really-an-image")
    findings = scan_paths(tmp_path, ["screen.png"])
    assert findings[0].rule == "FORBIDDEN_EVIDENCE_ARTIFACT"


def test_history_scanner_finds_old_token(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    p = tmp_path / "config.txt"
    historical_token = "ghp_" + ("A" * 36)
    p.write_text(historical_token + "\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "secret"], cwd=tmp_path, check=True)
    p.write_text("clean=true\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "clean"], cwd=tmp_path, check=True)

    report = scan_repository(tmp_path, history=True)
    assert any(f["rule"] == "GH_TOKEN" for f in report["findings"])


def test_history_scanner_finds_short_hardcoded_credential(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    p = tmp_path / "config.txt"
    p.write_text(("pass" + "word") + "=765432\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "secret"], cwd=tmp_path, check=True)
    p.write_text("clean=true\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "clean"], cwd=tmp_path, check=True)

    report = scan_repository(tmp_path, history=True)
    assert any(f["rule"] == "HARDCODED_CREDENTIAL" for f in report["findings"])
