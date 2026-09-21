import json

import pytest

from inginv.cli import _read_json_object


def test_read_json_object_accepts_mapping(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({"schema": "test"}), encoding="utf-8")
    assert _read_json_object(path, max_bytes=1024)["schema"] == "test"


def test_read_json_object_rejects_non_object(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain an object"):
        _read_json_object(path, max_bytes=1024)


def test_read_json_object_rejects_oversized_input(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({"payload": "x" * 64}), encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds size budget"):
        _read_json_object(path, max_bytes=16)
