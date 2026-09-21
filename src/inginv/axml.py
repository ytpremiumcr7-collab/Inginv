from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import csv
import io
import json
import struct
import xml.etree.ElementTree as ET
import zipfile

from .apk import validate_apk_archive

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
UTF8_FLAG = 0x00000100
NO_INDEX = 0xFFFFFFFF

TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class AxmlError(ValueError):
    pass


@dataclass
class AxmlAttribute:
    namespace: str | None
    name: str
    value: str


@dataclass
class AxmlNode:
    tag: str
    namespace: str | None = None
    attributes: list[AxmlAttribute] = field(default_factory=list)
    children: list["AxmlNode"] = field(default_factory=list)

    def attr(self, name: str) -> str | None:
        for item in self.attributes:
            if item.name == name:
                return item.value
        return None


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise AxmlError("truncated uint16")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise AxmlError("truncated uint32")
    return struct.unpack_from("<I", data, offset)[0]


def _decode_len8(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise AxmlError("truncated utf8 length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        if offset >= len(data):
            raise AxmlError("truncated utf8 extended length")
        return ((first & 0x7F) << 8) | data[offset], offset + 1
    return first, offset


def _decode_len16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    offset += 2
    if first & 0x8000:
        second = _u16(data, offset)
        offset += 2
        return ((first & 0x7FFF) << 16) | second, offset
    return first, offset


def _parse_string_pool(data: bytes, start: int, header_size: int, chunk_size: int) -> list[str]:
    if header_size < 28 or start + chunk_size > len(data):
        raise AxmlError("invalid string pool bounds")

    string_count = _u32(data, start + 8)
    style_count = _u32(data, start + 12)
    flags = _u32(data, start + 16)
    strings_start = _u32(data, start + 20)
    styles_start = _u32(data, start + 24)

    offsets_start = start + header_size
    if offsets_start + string_count * 4 + style_count * 4 > start + chunk_size:
        raise AxmlError("string pool offsets exceed chunk")

    offsets = [_u32(data, offsets_start + i * 4) for i in range(string_count)]
    string_base = start + strings_start
    string_limit = start + (styles_start if styles_start else chunk_size)
    utf8 = bool(flags & UTF8_FLAG)

    values: list[str] = []
    for relative in offsets:
        pos = string_base + relative
        if pos < string_base or pos >= string_limit:
            raise AxmlError("string offset outside pool")
        if utf8:
            _, pos = _decode_len8(data, pos)
            byte_len, pos = _decode_len8(data, pos)
            end = pos + byte_len
            if end > string_limit:
                raise AxmlError("utf8 string exceeds pool")
            values.append(data[pos:end].decode("utf-8", "replace"))
        else:
            char_len, pos = _decode_len16(data, pos)
            end = pos + char_len * 2
            if end > string_limit:
                raise AxmlError("utf16 string exceeds pool")
            values.append(data[pos:end].decode("utf-16le", "replace"))
    return values


def _s(strings: list[str], index: int) -> str | None:
    if index == NO_INDEX:
        return None
    if index >= len(strings):
        raise AxmlError(f"string index {index} out of range")
    return strings[index]


def _typed_value(strings: list[str], raw_index: int, data_type: int, value: int) -> str:
    if raw_index != NO_INDEX:
        return _s(strings, raw_index) or ""
    if data_type == TYPE_STRING:
        return _s(strings, value) or ""
    if data_type == TYPE_REFERENCE:
        return f"@0x{value:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{value:08x}"
    if data_type == TYPE_INT_DEC:
        return str(value)
    if data_type == TYPE_INT_HEX:
        return f"0x{value:x}"
    if data_type == TYPE_INT_BOOLEAN:
        return "true" if value else "false"
    if data_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", value))[0])
    if 0x1C <= data_type <= 0x1F:
        return f"#{value:08x}"
    return f"0x{value:08x}"


def parse_binary_axml(data: bytes) -> AxmlNode:
    if len(data) < 8:
        raise AxmlError("manifest is too small")
    root_type, root_header, root_size = struct.unpack_from("<HHI", data, 0)
    if root_type != RES_XML_TYPE:
        raise AxmlError("not Android binary XML")
    if root_header < 8 or root_size > len(data) or root_size < root_header:
        raise AxmlError("invalid XML root header")

    strings: list[str] = []
    stack: list[AxmlNode] = []
    root: AxmlNode | None = None
    offset = root_header

    while offset < root_size:
        if offset + 8 > root_size:
            raise AxmlError("truncated chunk header")
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if header_size < 8 or chunk_size < header_size or offset + chunk_size > root_size:
            raise AxmlError(f"invalid chunk at 0x{offset:x}")

        if chunk_type == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(data, offset, header_size, chunk_size)

        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            if not strings:
                raise AxmlError("start element before string pool")
            if header_size < 16 or chunk_size < 36:
                raise AxmlError("invalid start-element chunk")

            ext = offset + 16
            ns_index = _u32(data, ext)
            name_index = _u32(data, ext + 4)
            attribute_start = _u16(data, ext + 8)
            attribute_size = _u16(data, ext + 10)
            attribute_count = _u16(data, ext + 12)

            if attribute_size < 20:
                raise AxmlError("unsupported attribute size")
            first_attr = ext + attribute_start
            attrs_end = first_attr + attribute_count * attribute_size
            if first_attr < ext or attrs_end > offset + chunk_size:
                raise AxmlError("attribute table outside start-element chunk")

            node = AxmlNode(
                tag=_s(strings, name_index) or "",
                namespace=_s(strings, ns_index),
            )
            for i in range(attribute_count):
                pos = first_attr + i * attribute_size
                attr_ns = _u32(data, pos)
                attr_name = _u32(data, pos + 4)
                raw_value = _u32(data, pos + 8)
                value_size = _u16(data, pos + 12)
                if value_size < 8:
                    raise AxmlError("invalid typed value")
                data_type = data[pos + 15]
                value = _u32(data, pos + 16)
                node.attributes.append(AxmlAttribute(
                    namespace=_s(strings, attr_ns),
                    name=_s(strings, attr_name) or "",
                    value=_typed_value(strings, raw_value, data_type, value),
                ))

            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            else:
                raise AxmlError("multiple XML roots")
            stack.append(node)

        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            if not stack:
                raise AxmlError("end element without matching start")
            stack.pop()

        offset += chunk_size

    if root is None:
        raise AxmlError("no root element found")
    if stack:
        raise AxmlError("unclosed XML elements")
    return root


def _strip_ns(name: str) -> str:
    if name.startswith("{") and "}" in name:
        return name.split("}", 1)[1]
    return name


def _from_etree(element: ET.Element) -> AxmlNode:
    node = AxmlNode(tag=_strip_ns(element.tag))
    for key, value in element.attrib.items():
        namespace = None
        local = key
        if key.startswith("{") and "}" in key:
            namespace, local = key[1:].split("}", 1)
        node.attributes.append(AxmlAttribute(namespace, local, value))
    node.children = [_from_etree(child) for child in list(element)]
    return node


def parse_manifest_bytes(data: bytes) -> AxmlNode:
    stripped = data.lstrip()
    if stripped.startswith(b"<"):
        try:
            return _from_etree(ET.fromstring(data))
        except ET.ParseError as exc:
            raise AxmlError(str(exc)) from exc
    return parse_binary_axml(data)


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return None


def _children(node: AxmlNode, tag: str) -> list[AxmlNode]:
    return [child for child in node.children if child.tag == tag]


def _intent_filters(component: AxmlNode) -> list[dict]:
    filters: list[dict] = []
    for f in _children(component, "intent-filter"):
        filters.append({
            "actions": [n.attr("name") for n in _children(f, "action") if n.attr("name")],
            "categories": [n.attr("name") for n in _children(f, "category") if n.attr("name")],
            "data": [
                {a.name: a.value for a in n.attributes}
                for n in _children(f, "data")
            ],
        })
    return filters


def _component_risk_hints(component: dict) -> list[str]:
    hints: list[str] = []
    if component["exported_declared"] is True and not component["access_permissions"]:
        hints.append("exported_without_access_permission")
    actions = {a for f in component["intent_filters"] for a in f["actions"]}
    categories = {c for f in component["intent_filters"] for c in f["categories"]}
    if "android.intent.action.BOOT_COMPLETED" in actions or "android.intent.action.LOCKED_BOOT_COMPLETED" in actions:
        hints.append("boot_persistence_surface")
    if "android.intent.action.VIEW" in actions:
        hints.append("external_view_surface")
    if "android.intent.category.HOME" in categories:
        hints.append("home_launcher_surface")
    if component["direct_boot_aware"] is True:
        hints.append("direct_boot_surface")
    return hints


def build_manifest_model(root: AxmlNode) -> dict:
    if root.tag != "manifest":
        raise AxmlError(f"expected manifest root, got {root.tag!r}")

    uses_sdk = next(iter(_children(root, "uses-sdk")), None)
    app = next(iter(_children(root, "application")), None)

    permissions = []
    for child in root.children:
        if child.tag.startswith("uses-permission"):
            name = child.attr("name")
            if name:
                permissions.append({
                    "name": name,
                    "max_sdk_version": child.attr("maxSdkVersion"),
                    "tag": child.tag,
                })

    declared_permissions = []
    for child in _children(root, "permission"):
        declared_permissions.append({
            "name": child.attr("name"),
            "protection_level": child.attr("protectionLevel"),
        })

    components: list[dict] = []
    application_permission = app.attr("permission") if app else None
    if app:
        for child in app.children:
            if child.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
                continue
            filters = _intent_filters(child)
            exported_declared = _bool(child.attr("exported"))
            declared_permission = child.attr("permission")
            effective_permission = declared_permission or application_permission
            effective_read_permission = None
            effective_write_permission = None
            if child.tag == "provider":
                effective_read_permission = child.attr("readPermission") or effective_permission
                effective_write_permission = child.attr("writePermission") or effective_permission
            access_permissions = sorted({
                value for value in (
                    effective_permission,
                    effective_read_permission,
                    effective_write_permission,
                )
                if value
            })
            component = {
                "kind": child.tag,
                "name": child.attr("name"),
                "target_activity": child.attr("targetActivity"),
                "exported_declared": exported_declared,
                "enabled": _bool(child.attr("enabled")),
                "direct_boot_aware": _bool(child.attr("directBootAware")),
                "permission": declared_permission,
                "read_permission": child.attr("readPermission"),
                "write_permission": child.attr("writePermission"),
                "effective_permission": effective_permission,
                "effective_read_permission": effective_read_permission,
                "effective_write_permission": effective_write_permission,
                "access_permissions": access_permissions,
                "process": child.attr("process"),
                "authorities": child.attr("authorities"),
                "has_intent_filter": bool(filters),
                "intent_filters": filters,
            }
            component["risk_hints"] = _component_risk_hints(component)
            components.append(component)

    return {
        "package": root.attr("package"),
        "version_code": root.attr("versionCode"),
        "version_name": root.attr("versionName"),
        "min_sdk": uses_sdk.attr("minSdkVersion") if uses_sdk else None,
        "target_sdk": uses_sdk.attr("targetSdkVersion") if uses_sdk else None,
        "permissions": sorted(permissions, key=lambda x: x["name"]),
        "declared_permissions": sorted(declared_permissions, key=lambda x: x["name"] or ""),
        "application": {
            "name": app.attr("name") if app else None,
            "persistent": _bool(app.attr("persistent")) if app else None,
            "debuggable": _bool(app.attr("debuggable")) if app else None,
            "allow_backup": _bool(app.attr("allowBackup")) if app else None,
            "direct_boot_aware": _bool(app.attr("directBootAware")) if app else None,
            "uses_cleartext_traffic": _bool(app.attr("usesCleartextTraffic")) if app else None,
            "network_security_config": app.attr("networkSecurityConfig") if app else None,
            "permission": application_permission,
        },
        "components": components,
    }


def manifest_matrix(apk_path: str | Path) -> dict:
    with zipfile.ZipFile(apk_path) as zf:
        validate_apk_archive(zf)
        try:
            info = zf.getinfo("AndroidManifest.xml")
        except KeyError as exc:
            raise AxmlError("APK has no AndroidManifest.xml") from exc
        if info.file_size > 8 * 1024 * 1024:
            raise AxmlError("AndroidManifest.xml exceeds analysis budget")
        data = zf.read(info)
    return build_manifest_model(parse_manifest_bytes(data))


def write_component_csv(model: dict, path: str | Path) -> None:
    fields = [
        "kind", "name", "target_activity", "exported_declared", "enabled",
        "direct_boot_aware", "permission", "read_permission", "write_permission",
        "effective_permission", "effective_read_permission", "effective_write_permission",
        "access_permissions", "process", "authorities", "has_intent_filter", "risk_hints",
    ]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for component in model["components"]:
            row = {key: component.get(key) for key in fields}
            row["access_permissions"] = ",".join(component["access_permissions"])
            row["risk_hints"] = ",".join(component["risk_hints"])
            writer.writerow(row)


def manifest_json(model: dict) -> str:
    return json.dumps(model, indent=2, sort_keys=True)
