from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import html
import json
from pathlib import Path
from typing import Iterable

from .runtime import sanitize_runtime_text

EVIDENCE_STATES = {
    "STATIC_CONFIRMED",
    "RUNTIME_CONFIRMED",
    "CORRELATED",
    "INFERRED",
    "UNVERIFIED",
}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCE_LEVELS = {"low", "medium", "high"}


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceRef:
    source: str
    locator: str
    artifact_sha256: str | None = None
    capture_id: str | None = None
    record_id: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise EvidenceError("evidence source is required")
        if not self.locator.strip():
            raise EvidenceError("evidence locator is required")
        if self.artifact_sha256 is not None:
            value = self.artifact_sha256.lower()
            if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise EvidenceError("artifact_sha256 must be a 64-character hex digest")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: str
    title: str
    category: str
    evidence_state: str
    severity: str
    confidence: str
    consequence: str
    does_not_prove: str
    remediation: str
    evidence: tuple[EvidenceRef, ...]
    tags: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.evidence_state not in EVIDENCE_STATES:
            raise EvidenceError(f"invalid evidence state: {self.evidence_state}")
        if self.severity not in SEVERITIES:
            raise EvidenceError(f"invalid severity: {self.severity}")
        if self.confidence not in CONFIDENCE_LEVELS:
            raise EvidenceError(f"invalid confidence: {self.confidence}")
        if not self.evidence:
            raise EvidenceError("a finding requires at least one evidence reference")
        if not self.does_not_prove.strip():
            raise EvidenceError("does_not_prove is required")


def _canonical_identity(
    rule_id: str,
    category: str,
    evidence: Iterable[EvidenceRef],
) -> str:
    refs = sorted(
        (
            ref.source,
            ref.locator,
            ref.artifact_sha256 or "",
            ref.capture_id or "",
            ref.record_id or "",
        )
        for ref in evidence
    )
    payload = json.dumps(
        {"rule_id": rule_id, "category": category, "evidence": refs},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return payload


def stable_finding_id(
    rule_id: str,
    category: str,
    evidence: Iterable[EvidenceRef],
) -> str:
    digest = sha256(_canonical_identity(rule_id, category, evidence).encode("utf-8")).hexdigest()
    return f"ING-{digest[:20].upper()}"


def make_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    evidence_state: str,
    severity: str,
    confidence: str,
    consequence: str,
    does_not_prove: str,
    remediation: str,
    evidence: Iterable[EvidenceRef],
    tags: Iterable[str] = (),
    metadata: dict[str, object] | None = None,
) -> Finding:
    refs = tuple(evidence)
    finding_id = stable_finding_id(rule_id, category, refs)
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        title=title,
        category=category,
        evidence_state=evidence_state,
        severity=severity,
        confidence=confidence,
        consequence=consequence,
        does_not_prove=does_not_prove,
        remediation=remediation,
        evidence=refs,
        tags=tuple(sorted(set(tags))),
        metadata=dict(metadata or {}),
    )


def _sanitize(value: object) -> object:
    if isinstance(value, str):
        return sanitize_runtime_text(value)
    if isinstance(value, dict):
        return {str(key): _sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(item) for item in value]
    return value


def finding_to_dict(finding: Finding) -> dict:
    return _sanitize(asdict(finding))  # type: ignore[return-value]


def _manifest_findings(model: dict) -> list[Finding]:
    artifact = model.get("apk_sha256")
    findings: list[Finding] = []
    for component in model.get("components", []):
        name = component.get("name") or "<unnamed>"
        kind = component.get("kind") or "component"
        hints = set(component.get("risk_hints", []))
        if "exported_without_access_permission" not in hints:
            continue
        ref = EvidenceRef(
            source="android-manifest",
            locator=f"AndroidManifest.xml::{kind}:{name}",
            artifact_sha256=artifact,
            detail="exported=true and no effective component/application access permission",
        )
        findings.append(make_finding(
            rule_id="android.exported_without_access_permission",
            title=f"Exported Android {kind} without manifest access permission: {name}",
            category="android.exported-surface",
            evidence_state="STATIC_CONFIRMED",
            severity="medium",
            confidence="high",
            consequence=(
                "Other applications may be able to reach this component subject to Android platform "
                "rules and any authorization implemented inside the component."
            ),
            does_not_prove=(
                "Manifest reachability does not prove that the component performs a privileged action "
                "for an unauthorized caller or that exploitation is possible."
            ),
            remediation=(
                "Review caller authorization in the component implementation and, where appropriate, "
                "require a signature-level permission or make the component non-exported."
            ),
            evidence=(ref,),
            tags=("android", "manifest", "exported-component"),
        ))
    return findings


def _dex_findings(trace: dict) -> list[Finding]:
    artifact = trace.get("apk_sha256")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for item in trace.get("task_execute_paths", []):
        command = item.get("command") or "<unknown-command>"
        entry = item.get("entry_method") or item.get("dispatcher") or "<unknown-method>"
        for sink_path in item.get("sink_paths", []):
            sink = sink_path.get("sink") or "<unknown-sink>"
            path = list(sink_path.get("path", []))
            terminal = path[-1] if path else sink
            key = (str(command), str(entry), str(sink))
            if key in seen:
                continue
            seen.add(key)

            refs = [
                EvidenceRef(
                    source="dex-method",
                    locator=f"dex-method:{entry}",
                    artifact_sha256=artifact,
                    detail=f"command={command}",
                ),
                EvidenceRef(
                    source="dex-sink",
                    locator=f"dex-method:{terminal}",
                    artifact_sha256=artifact,
                    detail=f"sink={sink}; depth={sink_path.get('depth')}",
                ),
            ]
            findings.append(make_finding(
                rule_id="android.privileged_command_path",
                title=f"Privileged command path: {command} -> {sink}",
                category="android.privileged-capability",
                evidence_state="STATIC_CONFIRMED",
                severity="informational",
                confidence="high",
                consequence=(
                    "The APK contains a statically resolved command path from a task implementation "
                    "to a privileged Android or Java primitive."
                ),
                does_not_prove=(
                    "A static call path does not prove that the command was received, authorized, "
                    "or executed on a particular device."
                ),
                remediation=(
                    "Treat this as a capability inventory item; separately verify authorization, "
                    "transport integrity, caller trust and runtime execution evidence."
                ),
                evidence=refs,
                tags=("android", "dex", "capability", str(sink).lower()),
                metadata={"command": command, "sink": sink, "call_path": path},
            ))
    return findings


def _correlation_findings(correlation: dict) -> list[Finding]:
    capture_id = correlation.get("capture_id")
    findings: list[Finding] = []
    for item in correlation.get("correlations", []):
        correlation_id = item.get("correlation_id") or "correlation"
        state = item.get("evidence_state") or "UNVERIFIED"
        refs = (
            EvidenceRef(
                source="correlation",
                locator=f"correlation:{correlation_id}",
                capture_id=capture_id,
                record_id=correlation_id,
                detail=json.dumps(item, sort_keys=True, default=str),
            ),
        )
        findings.append(make_finding(
            rule_id=f"analysis.correlation.{correlation_id}",
            title=f"Static/runtime correlation: {correlation_id}",
            category="analysis.correlation",
            evidence_state=state if state in EVIDENCE_STATES else "UNVERIFIED",
            severity="informational",
            confidence="high" if state == "CORRELATED" else "medium",
            consequence=(
                "Independent static and runtime evidence support the same capability or identity claim."
            ),
            does_not_prove=str(item.get(
                "does_not_prove",
                "Correlation does not by itself prove a specific remote command was executed.",
            )),
            remediation=(
                "Preserve the underlying static and runtime records and require direct runtime evidence "
                "before asserting command execution."
            ),
            evidence=refs,
            tags=("correlation",),
        ))
    return findings


def findings_from_analysis(
    *,
    manifest_model: dict | None = None,
    dex_trace: dict | None = None,
    correlation: dict | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    if manifest_model:
        findings.extend(_manifest_findings(manifest_model))
    if dex_trace:
        findings.extend(_dex_findings(dex_trace))
    if correlation:
        findings.extend(_correlation_findings(correlation))

    dedup = {finding.finding_id: finding for finding in findings}
    return sorted(dedup.values(), key=lambda finding: finding.finding_id)


def build_report(
    findings: Iterable[Finding],
    *,
    metadata: dict[str, object] | None = None,
    generated_at: str | None = None,
) -> dict:
    ordered = sorted(findings, key=lambda finding: finding.finding_id)
    return {
        "schema": "inginv.findings.v1",
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "finding_count": len(ordered),
        "metadata": _sanitize(metadata or {}),
        "findings": [finding_to_dict(finding) for finding in ordered],
    }


def _md(value: object) -> str:
    """Escape untrusted evidence for Markdown renderers that allow raw HTML."""
    return html.escape(str(value), quote=True).replace("`", "\\`")


def report_markdown(report: dict) -> str:
    safe = _sanitize(report)
    lines = [
        "# Inginv findings report",
        "",
        f"Schema: `{_md(safe.get('schema', 'unknown'))}`  ",
        f"Generated: `{_md(safe.get('generated_at', 'unknown'))}`  ",
        f"Findings: **{_md(safe.get('finding_count', 0))}**",
        "",
    ]
    for finding in safe.get("findings", []):
        lines.extend([
            f"## {_md(finding['finding_id'])} — {_md(finding['title'])}",
            "",
            f"- Rule: `{_md(finding['rule_id'])}`",
            f"- Evidence state: `{_md(finding['evidence_state'])}`",
            f"- Severity: `{_md(finding['severity'])}`",
            f"- Confidence: `{_md(finding['confidence'])}`",
            f"- Category: `{_md(finding['category'])}`",
            "",
            f"**Consequence:** {_md(finding['consequence'])}",
            "",
            f"**Does not prove:** {_md(finding['does_not_prove'])}",
            "",
            f"**Remediation direction:** {_md(finding['remediation'])}",
            "",
            "**Evidence:**",
        ])
        for ref in finding["evidence"]:
            artifact = ref.get("artifact_sha256")
            suffix = f" (artifact `{_md(artifact)}`)" if artifact else ""
            lines.append(
                f"- `{_md(ref['locator'])}` via `{_md(ref['source'])}`{suffix}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def dump_report_json(report: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(_sanitize(report), indent=2, sort_keys=True), encoding="utf-8")


def dump_report_markdown(report: dict, path: str | Path) -> None:
    Path(path).write_text(report_markdown(report), encoding="utf-8")
