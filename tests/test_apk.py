from pathlib import Path
import zipfile

from inginv.apk import classify, extract_strings, summarize


def test_classify_core_apk_surfaces():
    assert classify("classes.dex") == "dex"
    assert classify("classes2.dex") == "dex"
    assert classify("lib/arm64-v8a/libx.so") == "native-library"
    assert classify("AndroidManifest.xml") == "manifest"
    assert classify("assets/server.bks") == "keystore"


def test_summary_hashes_every_file_without_leaking_parent_path(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex\ninstallApp\n")
    report = summarize(apk)
    assert report["zip_integrity"] == "ok"
    assert report["entry_count"] == 2
    assert report["counts"]["dex"] == 1
    assert report["path"] == "sample.apk"
    assert str(tmp_path) not in str(report)
    assert all(len(entry["sha256"]) == 64 for entry in report["entries"])


def test_string_export_does_not_reproduce_credential_values(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    login_name = "operator"
    credential_value = "654321"
    payload = (
        f"ssl://{login_name}:{credential_value}@example.invalid:1886/client?token=abcdef "
        f"installApp password={credential_value} username={login_name}"
    ).encode()
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", payload)

    report = extract_strings(apk)
    rendered = str(report)
    assert login_name not in rendered
    assert credential_value not in rendered
    assert "abcdef" not in rendered
    assert any(url.startswith("ssl://example.invalid:1886/client") for url in report["urls"])
    assert report["command_hits"][0]["commands"] == ["installApp"]
    assert "value" not in report["command_hits"][0]
    assert "value" not in report["credential_hints"][0]
