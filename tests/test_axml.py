import zipfile
from pathlib import Path

import pytest

from inginv.axml import AxmlError, build_manifest_model, manifest_matrix, parse_manifest_bytes


PLAINTEXT_MANIFEST = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.mdm" android:versionCode="7" android:versionName="1.2">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <permission android:name="com.example.CALL" android:protectionLevel="signature"/>
  <application android:persistent="true" android:allowBackup="false" android:directBootAware="true">
    <receiver android:name=".Boot" android:exported="true" android:directBootAware="true">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <service android:name=".Internal" android:exported="false"/>
  </application>
</manifest>
'''


def test_plaintext_manifest_model_has_components_and_permissions():
    model = build_manifest_model(parse_manifest_bytes(PLAINTEXT_MANIFEST))
    assert model["package"] == "com.example.mdm"
    assert model["target_sdk"] == "33"
    assert model["application"]["persistent"] is True
    assert model["permissions"][0]["name"] == "android.permission.INTERNET"
    assert model["declared_permissions"][0]["protection_level"] == "signature"
    receiver = next(c for c in model["components"] if c["kind"] == "receiver")
    assert receiver["exported_declared"] is True
    assert "boot_persistence_surface" in receiver["risk_hints"]
    assert "exported_without_access_permission" in receiver["risk_hints"]


def test_manifest_matrix_reads_apk(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", PLAINTEXT_MANIFEST)
    model = manifest_matrix(apk)
    assert len(model["components"]) == 2


def test_rejects_missing_manifest(tmp_path: Path):
    apk = tmp_path / "bad.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", b"dex")
    with pytest.raises(AxmlError, match="no AndroidManifest"):
        manifest_matrix(apk)


def test_rejects_truncated_binary_axml():
    with pytest.raises(AxmlError):
        parse_manifest_bytes(b"\x03\x00\x08\x00")


def test_application_permission_is_inherited_by_exported_component():
    xml = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <application android:permission="com.example.SIGNATURE">
        <service android:name=".Remote" android:exported="true"/>
      </application>
    </manifest>'''
    model = build_manifest_model(parse_manifest_bytes(xml))
    service = model["components"][0]
    assert service["permission"] is None
    assert service["effective_permission"] == "com.example.SIGNATURE"
    assert service["access_permissions"] == ["com.example.SIGNATURE"]
    assert "exported_without_access_permission" not in service["risk_hints"]


def test_provider_read_write_permissions_count_as_access_control():
    xml = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <application>
        <provider android:name=".Provider" android:exported="true"
          android:authorities="com.example.provider"
          android:readPermission="com.example.READ"
          android:writePermission="com.example.WRITE"/>
      </application>
    </manifest>'''
    model = build_manifest_model(parse_manifest_bytes(xml))
    provider = model["components"][0]
    assert provider["effective_read_permission"] == "com.example.READ"
    assert provider["effective_write_permission"] == "com.example.WRITE"
    assert set(provider["access_permissions"]) == {"com.example.READ", "com.example.WRITE"}
    assert "exported_without_access_permission" not in provider["risk_hints"]
