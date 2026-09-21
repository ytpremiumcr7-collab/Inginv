from inginv.runtime import collect_runtime, correlate_static_runtime, derive_runtime_facts, sanitize_runtime_text


def fake_runner_factory(outputs):
    def run(argv, timeout):
        joined = " ".join(argv)
        for needle, result in outputs:
            if needle in joined:
                return result
        return (0, b"", b"")
    return run


def test_sanitizer_removes_network_and_device_identifiers():
    serial_line = "ro." + "serialno=ABC123"
    wifi_line = ("SS" + 'ID="PrivateNetwork" ') + ("BS" + "SID=aa:bb:cc:dd:ee:ff")
    credential_line = ("author" + "ization") + "=super-secret-value"
    text = (
        serial_line + "\n" +
        wifi_line + " ip=192.168.1.25 remote=2001:db8::1\n" +
        credential_line
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


def test_runtime_facts_and_correlation_keep_execution_unknown():
    package = "com.example.mdm"
    outputs = [
        ("ro.product.model", (0, b"box\n", b"")),
        ("ro.product.device", (0, b"device\n", b"")),
        ("ro.build.display.id", (0, b"build\n", b"")),
        ("ro.build.version.sdk", (0, b"33\n", b"")),
        ("date +%Y-%m-%dT%H:%M:%S%z", (0, b"2026-09-20T12:00:00-0600\n", b"")),
        ("persist.sys.timezone", (0, b"America/Mexico_City\n", b"")),
        ("dumpsys device_policy", (0, f"Current Device Policy Manager state:\n  Device Owner:\n    package={package}\n  Enabled Device Admins:\n".encode(), b"")),
        ("pidof com.example.mdm", (0, b"2403\n", b"")),
        ("activity services", (0, f"ServiceRecord x {package}/.AgentService\n".encode(), b"")),
        ("jobscheduler", (0, f"JOB #1000/1 {package}/SystemJobService\n".encode(), b"")),
    ]
    bundle = collect_runtime(package, runner=fake_runner_factory(outputs))
    assert bundle["device"]["local_time"] == "2026-09-20T12:00:00-0600"
    assert bundle["device"]["timezone"] == "America/Mexico_City"

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
    assert report["observed_remote_command_execution"]["value"] is None


def test_device_owner_parser_does_not_match_target_elsewhere_in_dump():
    package = "com.example.mdm"
    other = "com.other.owner"
    outputs = [
        (
            "dumpsys device_policy",
            (
                0,
                (
                    "Current Device Policy Manager state:\n"
                    "  Device Owner:\n"
                    f"    admin=ComponentInfo{{{other}/.Admin}}\n"
                    f"    package={other}\n"
                    "  Enabled Device Admins (User 0):\n"
                    f"    {package}/.Admin:\n"
                ).encode(),
                b"",
            ),
        ),
    ]
    bundle = collect_runtime(package, runner=fake_runner_factory(outputs))
    facts = {f["fact_id"]: f for f in derive_runtime_facts(bundle)}
    assert facts["runtime.device_owner"]["evidence_state"] == "RUNTIME_CONFIRMED"
    assert facts["runtime.device_owner"]["value"] is False
    policy = next(r for r in bundle["records"] if r["name"] == "device_policy")
    assert package not in policy["stdout"]
    assert other not in policy["stdout"]


def test_failed_device_policy_collection_is_unknown_not_false():
    package = "com.example.mdm"
    outputs = [("dumpsys device_policy", (1, b"", b"permission denied"))]
    bundle = collect_runtime(package, runner=fake_runner_factory(outputs))
    facts = {f["fact_id"]: f for f in derive_runtime_facts(bundle)}
    assert facts["runtime.device_owner"]["evidence_state"] == "UNVERIFIED"
    assert facts["runtime.device_owner"]["value"] is None


def test_alarm_output_is_package_scoped():
    package = "com.example.mdm"
    unrelated = "com.private.unrelated"
    outputs = [
        (
            "dumpsys alarm",
            (
                0,
                (
                    f"alarm target={package}/.Receiver\n"
                    f"alarm target={unrelated}/.Receiver private_payload=should-not-survive\n"
                ).encode(),
                b"",
            ),
        ),
    ]
    bundle = collect_runtime(package, runner=fake_runner_factory(outputs))
    alarm = next(r for r in bundle["records"] if r["name"] == "alarms")
    assert package in alarm["stdout"]
    assert unrelated not in alarm["stdout"]
    assert "should-not-survive" not in alarm["stdout"]


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
    assert not any("ps -A" in args for args in rendered)
    assert not any(args.endswith(" logcat -d -t 20") for args in rendered)
