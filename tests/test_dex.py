import pytest

from inginv.dex import DexError, MethodRef, decode_code_units


def test_decodes_const_string_and_invoke():
    strings = ["screenShot", "other"]
    methods = [
        MethodRef(0, "Lx/A;", "a", "()V"),
        MethodRef(1, "Landroid/app/admin/DevicePolicyManager;", "reboot", "(Landroid/content/ComponentName;)V"),
    ]
    # const-string v0, string@0 ; invoke-virtual {}, method@1 ; return-void
    units = [
        0x001A, 0x0000,
        0x006E, 0x0001, 0x0000,
        0x000E,
    ]
    string_refs, calls = decode_code_units(units, strings, methods)
    assert string_refs == {"screenShot"}
    assert calls == {1}


def test_decodes_jumbo_string():
    strings = ["x"] * 70000
    strings[65537] = "factoryReset"
    methods = []
    units = [0x001B, 0x0001, 0x0001, 0x000E]
    string_refs, calls = decode_code_units(units, strings, methods)
    assert string_refs == {"factoryReset"}
    assert calls == set()


def test_rejects_invalid_dex():
    from inginv.dex import DexFile
    with pytest.raises(DexError):
        DexFile(b"not-a-dex")
