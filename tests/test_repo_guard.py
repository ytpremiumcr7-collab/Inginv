from pathlib import Path
import subprocess

from inginv.repo_guard import scan_repository, scan_text


def test_detects_private_key_without_reproducing_key_material():
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    findings = scan_text("bad.txt", marker + "\ncontents")
    assert findings[0].rule == "PRIVATE_KEY"
    assert findings[0].evidence == marker


def test_detects_hardcoded_password_and_redacts_value():
    secret = "this-is-a-real-looking-secret"
    findings = scan_text("cfg.py", f'password = "{secret}"')
    assert findings[0].rule == "HARDCODED_CREDENTIAL"
    assert secret not in findings[0].evidence


def test_ignores_explicit_example_secret():
    findings = scan_text("example.py", 'password = "example-not-a-real-secret"')
    assert not findings


def test_detects_device_identity_material():
    findings = scan_text("dump.txt", 'ro.serialno=ABC123456789\nSSID="PrivateWifi"')
    rules = {f.rule for f in findings}
    assert {"DEVICE_SERIAL", "WIFI_SSID"} <= rules


def test_history_scanner_finds_old_secret(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    p = tmp_path / "config.txt"
    p.write_text("password=this-is-a-history-secret\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "secret"], cwd=tmp_path, check=True)
    p.write_text("clean=true\n", encoding="utf-8")
    subprocess.run(["git", "add", "config.txt"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "clean"], cwd=tmp_path, check=True)

    report = scan_repository(tmp_path, history=True)
    assert any(f["rule"] == "HARDCODED_CREDENTIAL" for f in report["findings"])
