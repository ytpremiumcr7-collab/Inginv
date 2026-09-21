from pathlib import Path
import zipfile

import pytest

from inginv.apk import ApkSafetyError, validate_apk_archive


def test_archive_entry_count_budget(tmp_path: Path):
    apk = tmp_path / "many.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("a.txt", b"a")
        zf.writestr("b.txt", b"b")
    with zipfile.ZipFile(apk) as zf:
        with pytest.raises(ApkSafetyError, match="too many entries"):
            validate_apk_archive(zf, max_entries=1)


def test_archive_per_entry_budget(tmp_path: Path):
    apk = tmp_path / "large-entry.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("payload.bin", b"x" * 32)
    with zipfile.ZipFile(apk) as zf:
        with pytest.raises(ApkSafetyError, match="entry too large"):
            validate_apk_archive(zf, max_entry_uncompressed=16)


def test_archive_total_budget(tmp_path: Path):
    apk = tmp_path / "large-total.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("a.bin", b"a" * 12)
        zf.writestr("b.bin", b"b" * 12)
    with zipfile.ZipFile(apk) as zf:
        with pytest.raises(ApkSafetyError, match="uncompressed size exceeds budget"):
            validate_apk_archive(zf, max_total_uncompressed=20)
