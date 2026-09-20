from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import struct
import zipfile

from .apk import COMMAND_HINTS, file_sha256


class DexError(ValueError):
    pass


@dataclass(frozen=True)
class MethodRef:
    index: int
    owner: str
    name: str
    descriptor: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}->{self.name}{self.descriptor}"


@dataclass
class MethodCode:
    method: MethodRef
    code_off: int
    strings: set[str] = field(default_factory=set)
    calls: set[int] = field(default_factory=set)


SINK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("DEVICE_WIPE", "Landroid/app/admin/DevicePolicyManager;->wipeData"),
    ("DEVICE_REBOOT", "Landroid/app/admin/DevicePolicyManager;->reboot"),
    ("PACKAGE_INSTALL_CREATE", "Landroid/content/pm/PackageInstaller;->createSession"),
    ("PACKAGE_INSTALL_OPEN", "Landroid/content/pm/PackageInstaller;->openSession"),
    ("PACKAGE_INSTALL_COMMIT", "Landroid/content/pm/PackageInstaller$Session;->commit"),
    ("RUNTIME_EXEC", "Ljava/lang/Runtime;->exec"),
    ("PROCESS_BUILDER", "Ljava/lang/ProcessBuilder;->"),
    ("FILE_DELETE", "Ljava/io/File;->delete"),
    ("FILE_RENAME", "Ljava/io/File;->renameTo"),
    ("SETTINGS_SECURE_WRITE", "Landroid/provider/Settings$Secure;->put"),
    ("SETTINGS_GLOBAL_WRITE", "Landroid/provider/Settings$Global;->put"),
)

THIRD_PARTY_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/",
    "Ljava/", "Ljavax/", "Lokhttp3/", "Lokio/", "Lorg/json/", "Lorg/apache/",
)


def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise DexError("truncated uint16")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise DexError("truncated uint32")
    return struct.unpack_from("<I", data, off)[0]


def _uleb(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(5):
        if off >= len(data):
            raise DexError("truncated uleb128")
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
    raise DexError("uleb128 too large")


def _read_mutf8(data: bytes, off: int) -> str:
    _, pos = _uleb(data, off)
    end = data.find(b"\x00", pos)
    if end < 0:
        raise DexError("unterminated string_data_item")
    raw = data[pos:end]
    raw = raw.replace(b"\xc0\x80", b"\x00")
    return raw.decode("utf-8", "replace")


def _type_list(data: bytes, off: int, types: list[str]) -> list[str]:
    if off == 0:
        return []
    size = _u32(data, off)
    pos = off + 4
    result: list[str] = []
    for _ in range(size):
        idx = _u16(data, pos)
        pos += 2
        if idx >= len(types):
            raise DexError("type_list index out of range")
        result.append(types[idx])
    return result


def _instruction_width(units: list[int], index: int) -> int:
    unit = units[index]
    opcode = unit & 0xFF
    high = unit >> 8

    if opcode == 0x00 and high:
        if high == 0x01:
            if index + 1 >= len(units):
                return 1
            return 4 + 2 * units[index + 1]
        if high == 0x02:
            if index + 1 >= len(units):
                return 1
            return 2 + 4 * units[index + 1]
        if high == 0x03:
            if index + 3 >= len(units):
                return 1
            element_width = units[index + 1]
            size = units[index + 2] | (units[index + 3] << 16)
            return 4 + ((element_width * size + 1) // 2)
        return 1

    if opcode in {
        0x00,0x01,0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,
        0x12,0x1d,0x1e,0x21,0x27,0x28,
        *range(0x7b,0x90), *range(0xb0,0xd0),
    }:
        return 1
    if opcode in {
        0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29,
        *range(0x2d,0x3e), *range(0x44,0x6e), *range(0x90,0xb0),
        *range(0xd0,0xe3), 0xfe, 0xff,
    }:
        return 2
    if opcode in {
        0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c,
        *range(0x6e,0x73), *range(0x74,0x79), 0xfc, 0xfd,
    }:
        return 3
    if opcode in {0xfa, 0xfb}:
        return 4
    if opcode == 0x18:
        return 5
    return 1


def decode_code_units(
    units: list[int],
    strings: list[str],
    methods: list[MethodRef],
) -> tuple[set[str], set[int]]:
    string_refs: set[str] = set()
    calls: set[int] = set()
    i = 0
    while i < len(units):
        opcode = units[i] & 0xFF
        width = _instruction_width(units, i)
        if width <= 0 or i + width > len(units):
            break

        if opcode == 0x1A and i + 1 < len(units):
            idx = units[i + 1]
            if idx < len(strings):
                string_refs.add(strings[idx])
        elif opcode == 0x1B and i + 2 < len(units):
            idx = units[i + 1] | (units[i + 2] << 16)
            if idx < len(strings):
                string_refs.add(strings[idx])
        elif (0x6E <= opcode <= 0x72) or (0x74 <= opcode <= 0x78) or opcode in {0xFA, 0xFB}:
            if i + 1 < len(units):
                idx = units[i + 1]
                if idx < len(methods):
                    calls.add(idx)

        i += width
    return string_refs, calls


class DexFile:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        self.data = data
        self.name = name
        self.strings: list[str] = []
        self.types: list[str] = []
        self.methods: list[MethodRef] = []
        self.code: dict[int, MethodCode] = {}
        self._parse()

    def _parse(self) -> None:
        data = self.data
        if len(data) < 112 or not data.startswith(b"dex\n"):
            raise DexError(f"{self.name}: invalid DEX header")
        file_size = _u32(data, 32)
        header_size = _u32(data, 36)
        if file_size > len(data) or header_size < 112:
            raise DexError(f"{self.name}: invalid DEX bounds")

        string_ids_size, string_ids_off = _u32(data, 56), _u32(data, 60)
        type_ids_size, type_ids_off = _u32(data, 64), _u32(data, 68)
        proto_ids_size, proto_ids_off = _u32(data, 72), _u32(data, 76)
        method_ids_size, method_ids_off = _u32(data, 88), _u32(data, 92)
        class_defs_size, class_defs_off = _u32(data, 96), _u32(data, 100)

        self._check_table(string_ids_off, string_ids_size, 4)
        self._check_table(type_ids_off, type_ids_size, 4)
        self._check_table(proto_ids_off, proto_ids_size, 12)
        self._check_table(method_ids_off, method_ids_size, 8)
        self._check_table(class_defs_off, class_defs_size, 32)

        string_offsets = [_u32(data, string_ids_off + i * 4) for i in range(string_ids_size)]
        self.strings = [_read_mutf8(data, off) for off in string_offsets]

        type_string_indices = [_u32(data, type_ids_off + i * 4) for i in range(type_ids_size)]
        self.types = [self._string(idx) for idx in type_string_indices]

        protos: list[str] = []
        for i in range(proto_ids_size):
            off = proto_ids_off + i * 12
            return_type_idx = _u32(data, off + 4)
            parameters_off = _u32(data, off + 8)
            if return_type_idx >= len(self.types):
                raise DexError("return type index out of range")
            params = _type_list(data, parameters_off, self.types)
            protos.append("(" + "".join(params) + ")" + self.types[return_type_idx])

        for i in range(method_ids_size):
            off = method_ids_off + i * 8
            class_idx = _u16(data, off)
            proto_idx = _u16(data, off + 2)
            name_idx = _u32(data, off + 4)
            if class_idx >= len(self.types) or proto_idx >= len(protos):
                raise DexError("method id references out-of-range type/proto")
            self.methods.append(MethodRef(
                index=i,
                owner=self.types[class_idx],
                name=self._string(name_idx),
                descriptor=protos[proto_idx],
            ))

        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            class_data_off = _u32(data, off + 24)
            if class_data_off:
                self._parse_class_data(class_data_off)

    def _check_table(self, off: int, count: int, item_size: int) -> None:
        if count == 0:
            return
        if off == 0 or off + count * item_size > len(self.data):
            raise DexError(f"{self.name}: table outside file")

    def _string(self, idx: int) -> str:
        if idx >= len(self.strings):
            raise DexError("string index out of range")
        return self.strings[idx]

    def _parse_class_data(self, off: int) -> None:
        data = self.data
        static_fields, off = _uleb(data, off)
        instance_fields, off = _uleb(data, off)
        direct_methods, off = _uleb(data, off)
        virtual_methods, off = _uleb(data, off)

        for count in (static_fields, instance_fields):
            index = 0
            for _ in range(count):
                diff, off = _uleb(data, off)
                _, off = _uleb(data, off)
                index += diff

        for count in (direct_methods, virtual_methods):
            method_index = 0
            for _ in range(count):
                diff, off = _uleb(data, off)
                _, off = _uleb(data, off)
                code_off, off = _uleb(data, off)
                method_index += diff
                if method_index >= len(self.methods):
                    raise DexError("encoded method index out of range")
                if code_off:
                    self.code[method_index] = self._parse_code_item(method_index, code_off)

    def _parse_code_item(self, method_index: int, off: int) -> MethodCode:
        if off + 16 > len(self.data):
            raise DexError("code_item outside file")
        insns_size = _u32(self.data, off + 12)
        insns_off = off + 16
        end = insns_off + insns_size * 2
        if end > len(self.data):
            raise DexError("instruction stream outside file")
        units = list(struct.unpack_from(f"<{insns_size}H", self.data, insns_off)) if insns_size else []
        string_refs, calls = decode_code_units(units, self.strings, self.methods)
        return MethodCode(self.methods[method_index], off, string_refs, calls)


def _classify_owner(owner: str, first_party_prefixes: tuple[str, ...]) -> str:
    if first_party_prefixes and any(owner.startswith(prefix) for prefix in first_party_prefixes):
        return "first_party"
    if owner.startswith(THIRD_PARTY_PREFIXES):
        return "platform_or_library"
    return "unknown_app_or_library"


def _sink(method: MethodRef) -> str | None:
    full = method.full_name
    for sink_id, prefix in SINK_PATTERNS:
        if full.startswith(prefix):
            return sink_id
    return None


def _sink_full(full_name: str) -> str | None:
    for sink_id, prefix in SINK_PATTERNS:
        if full_name.startswith(prefix):
            return sink_id
    return None


def _owner_from_full_name(full_name: str) -> str:
    return full_name.split("->", 1)[0]


def _shortest_paths(
    seed: str,
    graph: dict[str, set[str]],
    max_depth: int,
) -> list[dict]:
    queue: list[tuple[str, list[str]]] = [(seed, [seed])]
    best_depth: dict[str, int] = {seed: 0}
    results: list[dict] = []

    while queue:
        current, path = queue.pop(0)
        depth = len(path) - 1
        if depth >= max_depth:
            continue

        for nxt in sorted(graph.get(current, ())):
            if nxt in path:
                continue
            next_path = path + [nxt]
            sink_id = _sink_full(nxt)
            if sink_id:
                results.append({
                    "sink": sink_id,
                    "path": next_path,
                    "depth": len(next_path) - 1,
                })
                continue

            next_depth = len(next_path) - 1
            if next_depth < best_depth.get(nxt, max_depth + 1):
                best_depth[nxt] = next_depth
                queue.append((nxt, next_path))

    # Keep only the shortest path per (sink, terminal method).
    dedup: dict[tuple[str, str], dict] = {}
    for item in results:
        key = (item["sink"], item["path"][-1])
        previous = dedup.get(key)
        if previous is None or item["depth"] < previous["depth"]:
            dedup[key] = item
    return sorted(dedup.values(), key=lambda x: (x["sink"], x["depth"], x["path"]))


def trace_apk(
    apk_path: str | Path,
    *,
    first_party_prefixes: tuple[str, ...] = (),
    max_depth: int = 12,
) -> dict:
    apk = Path(apk_path)
    if max_depth < 1 or max_depth > 64:
        raise ValueError("max_depth must be between 1 and 64")

    dexes: list[DexFile] = []
    with zipfile.ZipFile(apk) as zf:
        dex_names = sorted(
            name for name in zf.namelist()
            if Path(name).name == "classes.dex" or (
                Path(name).name.startswith("classes") and Path(name).name.endswith(".dex")
            )
        )
        for name in dex_names:
            dexes.append(DexFile(zf.read(name), name))

    # DEX method indexes are local to each file. Canonicalize by full Dalvik
    # signature so a call reference in classes.dex can connect to an
    # implementation that lives in classes2.dex.
    graph: dict[str, set[str]] = {}
    code_records: list[tuple[DexFile, MethodCode]] = []
    unique_method_refs: set[str] = set()

    for dex in dexes:
        unique_method_refs.update(method.full_name for method in dex.methods)
        for local_idx, code in dex.code.items():
            caller = code.method.full_name
            graph.setdefault(caller, set())
            for callee_idx in code.calls:
                if callee_idx < len(dex.methods):
                    graph[caller].add(dex.methods[callee_idx].full_name)
            code_records.append((dex, code))

    command_seeds: dict[str, set[str]] = {cmd: set() for cmd in COMMAND_HINTS}
    for _, code in code_records:
        exact_lower = {value.lower() for value in code.strings}
        for command in COMMAND_HINTS:
            if command.lower() in exact_lower:
                command_seeds[command].add(code.method.full_name)

    command_paths: list[dict] = []
    for command in sorted(command_seeds):
        for seed in sorted(command_seeds[command]):
            command_paths.append({
                "command": command,
                "seed_method": seed,
                "seed_owner_classification": _classify_owner(
                    _owner_from_full_name(seed), first_party_prefixes
                ),
                "sink_paths": _shortest_paths(seed, graph, max_depth),
            })

    sink_callers: list[dict] = []
    for caller, callees in graph.items():
        for callee in callees:
            sink_id = _sink_full(callee)
            if not sink_id:
                continue
            sink_callers.append({
                "sink": sink_id,
                "caller": caller,
                "caller_owner_classification": _classify_owner(
                    _owner_from_full_name(caller), first_party_prefixes
                ),
                "callee": callee,
            })

    return {
        "apk_sha256": file_sha256(apk),
        "dex_count": len(dexes),
        "dex_files": [d.name for d in dexes],
        "method_reference_count": sum(len(d.methods) for d in dexes),
        "unique_method_signature_count": len(unique_method_refs),
        "methods_with_code_count": len(code_records),
        "first_party_prefixes": list(first_party_prefixes),
        "evidence_semantics": {
            "call_edge": "STATIC_CONFIRMED invocation reference; does not prove runtime execution",
            "command_seed": "method contains an exact const-string command identifier",
            "sink_path": "shortest static invoke path from command-seed method to privileged sink",
            "cross_dex": "method references are canonicalized by full Dalvik signature across DEX files",
        },
        "command_paths": command_paths,
        "sink_callers": sorted(sink_callers, key=lambda x: (x["sink"], x["caller"])),
    }

