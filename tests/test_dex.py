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


def test_goto16_width_keeps_decoder_aligned():
    strings = ["screenShot"]
    methods = []
    # goto/16 uses two code units; const-string follows immediately after it.
    units = [0x0029, 0x0000, 0x001A, 0x0000, 0x000E]
    string_refs, _ = decode_code_units(units, strings, methods)
    assert string_refs == {"screenShot"}


def test_cross_dex_style_graph_can_continue_by_signature():
    from inginv.dex import _shortest_paths
    seed = "Lapp/Dispatcher;->route()V"
    bridge = "Lapp/Task;->execute()V"
    sink = "Landroid/app/admin/DevicePolicyManager;->reboot(Landroid/content/ComponentName;)V"
    graph = {seed: {bridge}, bridge: {sink}}
    paths = _shortest_paths(seed, graph, 4)
    assert paths[0]["sink"] == "DEVICE_REBOOT"
    assert paths[0]["path"] == [seed, bridge, sink]


def test_command_comparison_resolves_concrete_task_constructor():
    import struct
    from types import SimpleNamespace
    from inginv.dex import MethodCode, _discover_dispatches_in_method

    equals = MethodRef(
        0,
        "Ljava/lang/String;",
        "equals",
        "(Ljava/lang/Object;)Z",
    )
    dispatcher = MethodRef(1, "Lapp/PolicyBroker;", "takeOrder", "()V")

    # const-string v1, "reboot"
    # invoke-virtual {v0, v1}, String.equals
    # move-result v2
    # if-eqz v2, +5 code units (skip matching block)
    # new-instance v3, RebootTask
    # return-void
    units = [
        0x011A, 0x0000,
        0x206E, 0x0000, 0x0010,
        0x020A,
        0x0238, 0x0005,
        0x0322, 0x0000,
        0x000E,
    ]
    data = bytearray(16 + len(units) * 2)
    struct.pack_into("<I", data, 12, len(units))
    struct.pack_into(f"<{len(units)}H", data, 16, *units)

    dex = SimpleNamespace(
        data=bytes(data),
        strings=["reboot"],
        types=["Lapp/RebootTask;"],
        methods=[equals],
    )
    code = MethodCode(dispatcher, 0)
    discoveries = _discover_dispatches_in_method(dex, code)
    assert discoveries[0]["command"] == "reboot"
    assert discoveries[0]["task_types"] == ["Lapp/RebootTask;"]
    assert discoveries[0]["confidence"] == "high"


def test_polymorphic_controller_edge_reaches_device_policy_sink():
    from inginv.dex import _add_polymorphic_edges, _shortest_paths

    task = "Lapp/RebootTask;->execute()V"
    interface_call = "Lapp/IDeviceController;->reboot()V"
    implementation = "Lapp/DeviceController;->reboot()V"
    sink = "Landroid/app/admin/DevicePolicyManager;->reboot(Landroid/content/ComponentName;)V"

    graph = {
        task: {interface_call},
        implementation: {sink},
    }
    supertypes = {
        "Lapp/IDeviceController;": {"Ljava/lang/Object;"},
        "Lapp/DeviceController;": {"Ljava/lang/Object;", "Lapp/IDeviceController;"},
        "Lapp/RebootTask;": {"Ljava/lang/Object;"},
    }
    added = _add_polymorphic_edges(graph, {task, implementation}, supertypes)
    assert added == 1
    assert implementation in graph[interface_call]

    paths = _shortest_paths(task, graph, 6)
    assert paths[0]["sink"] == "DEVICE_REBOOT"
    assert paths[0]["path"] == [task, interface_call, implementation, sink]


@pytest.mark.parametrize(
    ("sink_method", "expected_sink"),
    [
        (
            "Landroid/content/pm/PackageInstaller$Session;->commit(Landroid/content/IntentSender;)V",
            "PACKAGE_INSTALL_COMMIT",
        ),
        (
            "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
            "RUNTIME_EXEC",
        ),
        (
            "Ljava/io/File;->delete()Z",
            "FILE_DELETE",
        ),
    ],
)
def test_required_privileged_sink_regressions(sink_method, expected_sink):
    from inginv.dex import _shortest_paths

    seed = "Lapp/Task;->execute()V"
    bridge = "Lapp/Controller;->apply()V"
    graph = {seed: {bridge}, bridge: {sink_method}}
    paths = _shortest_paths(seed, graph, 4)
    assert paths
    assert paths[0]["sink"] == expected_sink
    assert paths[0]["path"][-1] == sink_method



def test_d8_two_stage_string_switch_resolves_concrete_task():
    import struct
    from types import SimpleNamespace
    from inginv.dex import MethodCode, _discover_dispatches_in_method

    equals = MethodRef(0, "Ljava/lang/String;", "equals", "(Ljava/lang/Object;)Z")
    dispatcher = MethodRef(1, "Lapp/PolicyBroker;", "takeOrder", "()V")
    units = [
        0x061A, 0x0000,
        0x206E, 0x0000, 0x0064,
        0x040A,
        0x0439, 0x0004,
        0x0029, 0x0004,
        0x0512,
        0x0128,
        0x052B, 0x000A, 0x0000,
        0x0529, 0x0000,
        0x0322, 0x0000,
        0x0128,
        0x000E,
        0x0000,
        0x0100, 0x0001,
        0x0000, 0x0000,
        0x0005, 0x0000,
    ]
    data = bytearray(16 + len(units) * 2)
    struct.pack_into("<I", data, 12, len(units))
    struct.pack_into(f"<{len(units)}H", data, 16, *units)
    dex = SimpleNamespace(
        data=bytes(data),
        strings=["reboot"],
        types=["Lapp/RebootTask;"],
        methods=[equals],
    )
    code = MethodCode(dispatcher, 0)
    discoveries = _discover_dispatches_in_method(dex, code)
    assert discoveries[0]["command"] == "reboot"
    assert discoveries[0]["task_types"] == ["Lapp/RebootTask;"]
    assert discoveries[0]["resolution"] == "string-switch"
    assert discoveries[0]["confidence"] == "high"


def test_concrete_runnable_scheduler_adds_only_type_proven_edge():
    import struct
    from types import SimpleNamespace
    from inginv.dex import MethodCode, _add_runnable_dispatch_edges

    ctor = MethodRef(0, "Lapp/Worker;", "<init>", "()V")
    add = MethodRef(1, "Lapp/ThreadPool;", "add", "(Ljava/lang/Runnable;)Z")
    caller = MethodRef(2, "Lapp/Manager;", "start", "()V")
    units = [
        0x0122, 0x0000,
        0x1070, 0x0000, 0x0001,
        0x206E, 0x0001, 0x0010,
        0x000E,
    ]
    data = bytearray(16 + len(units) * 2)
    struct.pack_into("<I", data, 12, len(units))
    struct.pack_into(f"<{len(units)}H", data, 16, *units)
    dex = SimpleNamespace(data=bytes(data), types=["Lapp/Worker;"], methods=[ctor, add])
    code = MethodCode(caller, 0)
    graph = {caller.full_name: set()}
    edges = _add_runnable_dispatch_edges(
        graph,
        [(dex, code)],
        {"Lapp/Worker;->run()V"},
        {"Lapp/Worker;": {"Ljava/lang/Object;", "Ljava/lang/Runnable;"}},
    )
    assert graph[caller.full_name] == {"Lapp/Worker;->run()V"}
    assert len(edges) == 1
    assert edges[0]["runnable_type"] == "Lapp/Worker;"


def test_scheduler_does_not_assume_run_method_means_runnable():
    import struct
    from types import SimpleNamespace
    from inginv.dex import MethodCode, _add_runnable_dispatch_edges

    ctor = MethodRef(0, "Lapp/NotRunnable;", "<init>", "()V")
    add = MethodRef(1, "Lapp/ThreadPool;", "add", "(Ljava/lang/Runnable;)Z")
    caller = MethodRef(2, "Lapp/Manager;", "start", "()V")
    units = [
        0x0122, 0x0000,
        0x1070, 0x0000, 0x0001,
        0x206E, 0x0001, 0x0010,
        0x000E,
    ]
    data = bytearray(16 + len(units) * 2)
    struct.pack_into("<I", data, 12, len(units))
    struct.pack_into(f"<{len(units)}H", data, 16, *units)
    dex = SimpleNamespace(
        data=bytes(data),
        types=["Lapp/NotRunnable;"],
        methods=[ctor, add],
    )
    code = MethodCode(caller, 0)
    graph = {caller.full_name: set()}
    edges = _add_runnable_dispatch_edges(
        graph,
        [(dex, code)],
        {"Lapp/NotRunnable;->run()V"},
        {"Lapp/NotRunnable;": {"Ljava/lang/Object;"}},
    )
    assert not edges
    assert not graph[caller.full_name]
