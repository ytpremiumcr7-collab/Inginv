from pathlib import Path
import zipfile

from inginv.apk import classify, summarize


def test_classify_core_apk_surfaces():
    assert classify("classes.dex") == "dex"
    assert classify("classes2.dex") == "dex"
    assert classify("lib/arm64-v8a/libx.so") == "native-library"
    assert classify("AndroidManifest.xml") == "manifest"
    assert classify("assets/server.bks") == "keystore"


def test_summary_hashes_every_file(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest")
        zf.writestr("classes.dex", b"dex\ninstallApp\n")
    report = summarize(apk)
    assert report["zip_integrity"] == "ok"
    assert report["entry_count"] == 2
    assert report["counts"]["dex"] == 1
    assert all(len(entry["sha256"]) == 64 for entry in report["entries"])
