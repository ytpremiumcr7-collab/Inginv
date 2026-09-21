from inginv.evidence import (
    EvidenceRef,
    build_report,
    findings_from_analysis,
    make_finding,
    report_markdown,
)


APK_HASH = "a" * 64


def test_finding_id_is_stable_across_severity_changes():
    ref = EvidenceRef(
        source="dex-method",
        locator="dex-method:Lapp/Task;->execute()V",
        artifact_sha256=APK_HASH,
    )
    common = dict(
        title="Capability path",
        category="android.privileged-capability",
        evidence_state="STATIC_CONFIRMED",
        confidence="high",
        consequence="A privileged primitive is statically reachable.",
        does_not_prove="Static reachability does not prove runtime execution.",
        remediation="Verify authorization and runtime evidence separately.",
        evidence=(ref,),
    )
    low = make_finding(severity="informational", **common)
    high = make_finding(severity="high", **common)
    assert low.finding_id == high.finding_id


def test_manifest_adapter_keeps_capability_and_exploitability_separate():
    manifest = {
        "apk_sha256": APK_HASH,
        "components": [
            {
                "kind": "service",
                "name": ".Remote",
                "risk_hints": ["exported_without_access_permission"],
            }
        ],
    }
    findings = findings_from_analysis(manifest_model=manifest)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence_state == "STATIC_CONFIRMED"
    assert finding.severity == "medium"
    assert "does not prove" in finding.does_not_prove.lower()
    assert finding.evidence[0].artifact_sha256 == APK_HASH


def test_dex_adapter_emits_method_level_provenance():
    trace = {
        "apk_sha256": APK_HASH,
        "task_execute_paths": [
            {
                "command": "reboot",
                "entry_method": "Lapp/RebootTask;->execute()V",
                "sink_paths": [
                    {
                        "sink": "DEVICE_REBOOT",
                        "depth": 2,
                        "path": [
                            "Lapp/RebootTask;->execute()V",
                            "Lapp/DeviceController;->reboot()V",
                            "Landroid/app/admin/DevicePolicyManager;->reboot()V",
                        ],
                    }
                ],
            }
        ],
    }
    findings = findings_from_analysis(dex_trace=trace)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "informational"
    assert finding.metadata["command"] == "reboot"
    assert all(ref.locator.startswith("dex-method:") for ref in finding.evidence)


def test_report_markdown_is_deterministic_for_fixed_timestamp():
    ref = EvidenceRef(source="runtime", locator="runtime-record:test")
    finding = make_finding(
        title="Report test",
        category="test",
        evidence_state="RUNTIME_CONFIRMED",
        severity="informational",
        confidence="high",
        consequence="Test only.",
        does_not_prove="Test only.",
        remediation="None.",
        evidence=(ref,),
    )
    report = build_report([finding], generated_at="2026-09-20T00:00:00+00:00")
    markdown = report_markdown(report)
    assert finding.finding_id in markdown
    assert "RUNTIME_CONFIRMED" in markdown


def test_correlation_adapter_preserves_capture_id():
    correlation = {
        "capture_id": "capture-123",
        "correlations": [
            {
                "correlation_id": "package.identity",
                "evidence_state": "CORRELATED",
                "does_not_prove": "Identity correlation does not prove command execution.",
            }
        ],
    }
    findings = findings_from_analysis(correlation=correlation)
    assert findings[0].evidence[0].capture_id == "capture-123"
    assert findings[0].evidence_state == "CORRELATED"
