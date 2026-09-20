from inginv.runtime import collect_runtime, correlate_static_runtime, sanitize_runtime_text


def fake_runner_factory(outputs):
    def run(argv, timeout):
        logical = tuple(argv[-len(argv):])
        joined = " ".join(argv)
        for needle, result in outputs:
            if needle in joined:
                return result
        return (0, b"", b"")
    return run


def test_sanitizer_removes_network_and_device_identifiers():
    text = (
        "ro.serialno=ABC123\n"
        'SSID="PrivateNetwork" BSSID=aa:bb:cc:dd:ee:ff '
        "ip=192.168.1.25 remote=2001:db8::1\n"
        "authorization=super-secret-value"
    )
    sanitized = sanitize_runtime_text(text)
    assert "ABC123" not in sanitized
    assert "PrivateNetwork" not in sanitized
    assert "aa:bb:cc:dd:ee:ff" not in sanitized
    assert "192.168.1.25" not in sanitized
    assert "2001:db8::1" not in sanitized
    assert "super-secret-value" not in sanitized


def test_collector_never_serializes_adb_selector():
    secret_selector = "DEVICE-SERIAL-PRIVATE"
    outputs = [
        ("ro.product.model", (0, b"X96Q\n", b"")),
        ("ro.product.device", (0, b"eros-p1\n", b"")),
        ("ro.build.display.id", (0, b"build\n", b"")),
        ("ro.build.version.sdk", (0, b"29\n", b"")),
    ]
    bundle = collect_runtime(
        "com.example.mdm",
        serial=secret_selector,
        runner=fake_runner_factory(outputs),
    )
    rendered = str(bundle)
    assert secret_selector not in rendered
    assert bundle["privacy"]["adb_serial_stored"] is False


def test_runtime_facts_and_correlation_keep_execution_unverified():
    package = "com.example.mdm"
    outputs = [
        ("ro.product.model", (0, b"box\n", b"")),
        ("ro.product.device", (0, b"device\n", b"")),
        ("ro.build.display.id", (0, b"build\n", b"")),
        ("ro.build.version.sdk", (0, b"33\n", b"")),
        ("dumpsys device_policy", (0, f"Device Owner:\n package={package}\n".encode(), b"")),
        ("ps -A", (0, f"system 123 1 S {package}\n".encode(), b"")),
        ("activity services", (0, f"ServiceRecord x {package}/.AgentService\n".encode(), b"")),
        ("jobscheduler", (0, f"JOB #1000/1 {package}/SystemJobService\n".encode(), b"")),
    ]
    bundle = collect_runtime(package, runner=fake_runner_factory(outputs))
    manifest = {"package": package}
    dex = {
        "task_execute_paths": [
            {
                "command": "reboot",
                "sink_paths": [{"sink": "DEVICE_REBOOT", "path": ["a", "b"]}],
            }
        ]
    }
    report = correlate_static_runtime(
        runtime_bundle=bundle,
        manifest_model=manifest,
        dex_trace=dex,
    )

    assert any(c["correlation_id"] == "package.identity" for c in report["correlations"])
    assert any(c["correlation_id"] == "privileged.capability_and_authority" for c in report["correlations"])
    assert report["observed_remote_command_execution"]["evidence_state"] == "UNVERIFIED"
    assert report["observed_remote_command_execution"]["value"] is False


def test_network_and_logcat_are_opt_in_and_logcat_is_pid_scoped():
    seen = []

    def runner(argv, timeout):
        seen.append(list(argv))
        joined = " ".join(argv)
        if "pidof com.example.mdm" in joined:
            return (0, b"2403\n", b"")
        return (0, b"", b"")

    collect_runtime(
        "com.example.mdm",
        include_network=True,
        logcat_lines=20,
        runner=runner,
    )
    rendered = [" ".join(args) for args in seen]
    assert any("dumpsys connectivity" in args for args in rendered)
    assert any("--pid=2403" in args and "-t 20" in args for args in rendered)
    assert not any(args.endswith(" logcat -d -t 20") for args in rendered)
