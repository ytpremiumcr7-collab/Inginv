from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import struct
import zipfile

from .apk import COMMAND_HINTS, MAX_ENTRY_UNCOMPRESSED, file_sha256, validate_apk_archive


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
        self.class_supertypes: dict[str, set[str]] = {}
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
            class_idx = _u32(data, off)
            superclass_idx = _u32(data, off + 8)
            interfaces_off = _u32(data, off + 12)
            if class_idx >= len(self.types):
                raise DexError("class_def class index out of range")
            owner = self.types[class_idx]
            parents: set[str] = set()
            if superclass_idx != 0xFFFFFFFF:
                if superclass_idx >= len(self.types):
                    raise DexError("class_def superclass index out of range")
                parents.add(self.types[superclass_idx])
            parents.update(_type_list(data, interfaces_off, self.types))
            self.class_supertypes[owner] = parents

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



def _method_parts(full_name: str) -> tuple[str, str, str]:
    owner, rest = full_name.split("->", 1)
    name, descriptor_tail = rest.split("(", 1)
    return owner, name, "(" + descriptor_tail


def _is_subtype(
    candidate: str,
    target: str,
    supertypes: dict[str, set[str]],
    cache: dict[tuple[str, str], bool],
) -> bool:
    key = (candidate, target)
    if key in cache:
        return cache[key]
    if candidate == target:
        cache[key] = True
        return True
    seen: set[str] = set()
    stack = list(supertypes.get(candidate, ()))
    while stack:
        parent = stack.pop()
        if parent == target:
            cache[key] = True
            return True
        if parent in seen:
            continue
        seen.add(parent)
        stack.extend(supertypes.get(parent, ()))
    cache[key] = False
    return False


def _add_polymorphic_edges(
    graph: dict[str, set[str]],
    code_methods: set[str],
    supertypes: dict[str, set[str]],
    *,
    max_candidates_per_signature: int = 64,
) -> int:
    implementations: dict[tuple[str, str], list[str]] = {}
    for full in code_methods:
        _, name, descriptor = _method_parts(full)
        implementations.setdefault((name, descriptor), []).append(full)

    cache: dict[tuple[str, str], bool] = {}
    added = 0
    callees = {callee for values in graph.values() for callee in values}
    for callee in sorted(callees):
        target_owner, name, descriptor = _method_parts(callee)
        if target_owner not in supertypes:
            continue
        candidates = implementations.get((name, descriptor), ())
        if len(candidates) > max_candidates_per_signature:
            continue
        for implementation in candidates:
            impl_owner, _, _ = _method_parts(implementation)
            if impl_owner == target_owner:
                continue
            if _is_subtype(impl_owner, target_owner, supertypes, cache):
                graph.setdefault(callee, set()).add(implementation)
                added += 1
    return added


def _descriptor_parameters(descriptor: str) -> list[str]:
    if not descriptor.startswith("("):
        return []
    params: list[str] = []
    index = 1
    while index < len(descriptor) and descriptor[index] != ")":
        start = index
        while index < len(descriptor) and descriptor[index] == "[":
            index += 1
        if index >= len(descriptor):
            break
        if descriptor[index] == "L":
            end = descriptor.find(";", index)
            if end < 0:
                break
            index = end + 1
        else:
            index += 1
        params.append(descriptor[start:index])
    return params


def _invoke_argument_registers(record: dict) -> list[tuple[str, int]]:
    method = record.get("method")
    registers = list(record.get("registers", []))
    opcode = record.get("opcode")
    if not isinstance(method, str) or "->" not in method or "(" not in method:
        return []
    descriptor = "(" + method.split("(", 1)[1]
    params = _descriptor_parameters(descriptor)
    is_static = opcode in {0x71, 0x77}
    reg_index = 0 if is_static else 1
    result: list[tuple[str, int]] = []
    for param in params:
        if reg_index >= len(registers):
            break
        result.append((param, registers[reg_index]))
        reg_index += 2 if param in {"J", "D"} else 1
    return result


def _add_runnable_dispatch_edges(
    graph: dict[str, set[str]],
    code_records: list[tuple[DexFile, MethodCode]],
    code_methods: set[str],
    supertypes: dict[str, set[str]],
) -> list[dict]:
    """Resolve concrete Runnable objects handed to scheduling APIs.

    The object must be allocated in the same method/register, implement
    java.lang.Runnable in the parsed hierarchy, and expose run()V in the APK.
    """
    cache: dict[tuple[str, str], bool] = {}
    edges: list[dict] = []
    for dex, code in code_records:
        concrete_by_reg: dict[int, str] = {}
        for record in _decode_dispatch_records(dex, code):
            kind = record.get("kind")
            if kind == "new-instance":
                register = record.get("register")
                type_name = record.get("type")
                if isinstance(register, int) and isinstance(type_name, str):
                    concrete_by_reg[register] = type_name
                continue
            if kind != "invoke":
                continue
            for param, register in _invoke_argument_registers(record):
                if param != "Ljava/lang/Runnable;":
                    continue
                concrete = concrete_by_reg.get(register)
                if not concrete:
                    continue
                if not _is_subtype(concrete, "Ljava/lang/Runnable;", supertypes, cache):
                    continue
                run_method = concrete + "->run()V"
                if run_method not in code_methods:
                    continue
                caller = code.method.full_name
                if run_method in graph.setdefault(caller, set()):
                    continue
                graph[caller].add(run_method)
                edges.append({
                    "caller": caller,
                    "scheduler": record.get("method"),
                    "runnable_type": concrete,
                    "run_method": run_method,
                    "evidence": (
                        "same-method concrete new-instance passed as Runnable; "
                        "type hierarchy confirms Runnable"
                    ),
                })
    return sorted(edges, key=lambda x: (x["caller"], x["scheduler"], x["run_method"]))


def _signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _signed32(low: int, high: int) -> int:
    value = low | (high << 16)
    return value - 0x100000000 if value & 0x80000000 else value


def _switch_cases(units: list[int], switch_offset: int, opcode: int) -> dict[int, int]:
    if switch_offset + 2 >= len(units):
        return {}
    payload_offset = switch_offset + _signed32(
        units[switch_offset + 1], units[switch_offset + 2]
    )
    if payload_offset < 0 or payload_offset + 2 > len(units):
        return {}
    ident = units[payload_offset]
    size = units[payload_offset + 1]
    cases: dict[int, int] = {}

    if opcode == 0x2B and ident == 0x0100:
        if payload_offset + 4 + size * 2 > len(units):
            return {}
        first_key = _signed32(units[payload_offset + 2], units[payload_offset + 3])
        targets_off = payload_offset + 4
        for index in range(size):
            rel = _signed32(
                units[targets_off + index * 2],
                units[targets_off + index * 2 + 1],
            )
            cases[first_key + index] = switch_offset + rel
    elif opcode == 0x2C and ident == 0x0200:
        keys_off = payload_offset + 2
        targets_off = keys_off + size * 2
        if targets_off + size * 2 > len(units):
            return {}
        for index in range(size):
            key = _signed32(
                units[keys_off + index * 2],
                units[keys_off + index * 2 + 1],
            )
            rel = _signed32(
                units[targets_off + index * 2],
                units[targets_off + index * 2 + 1],
            )
            cases[key] = switch_offset + rel
    return cases


def _invoke_registers(units: list[int], index: int, opcode: int) -> list[int]:
    if 0x6E <= opcode <= 0x72 or opcode in {0xFA}:
        first = units[index]
        count = (first >> 12) & 0xF
        g = (first >> 8) & 0xF
        packed = units[index + 2] if index + 2 < len(units) else 0
        regs = [
            packed & 0xF,
            (packed >> 4) & 0xF,
            (packed >> 8) & 0xF,
            (packed >> 12) & 0xF,
            g,
        ]
        return regs[:count]
    if 0x74 <= opcode <= 0x78 or opcode in {0xFB}:
        count = (units[index] >> 8) & 0xFF
        start = units[index + 2] if index + 2 < len(units) else 0
        return list(range(start, start + count))
    return []


def _decode_dispatch_records(dex: DexFile, code: MethodCode) -> list[dict]:
    insns_size = _u32(dex.data, code.code_off + 12)
    insns_off = code.code_off + 16
    units = list(struct.unpack_from(f"<{insns_size}H", dex.data, insns_off)) if insns_size else []
    records: list[dict] = []
    i = 0
    while i < len(units):
        opcode = units[i] & 0xFF
        width = _instruction_width(units, i)
        if width <= 0 or i + width > len(units):
            break
        record: dict = {"offset": i, "opcode": opcode, "width": width}

        if opcode == 0x1A and i + 1 < len(units):
            record.update(kind="const-string", register=(units[i] >> 8) & 0xFF, string_index=units[i + 1])
        elif opcode == 0x1B and i + 2 < len(units):
            record.update(
                kind="const-string",
                register=(units[i] >> 8) & 0xFF,
                string_index=units[i + 1] | (units[i + 2] << 16),
            )
        elif opcode == 0x12:
            register = (units[i] >> 8) & 0xF
            literal = (units[i] >> 12) & 0xF
            if literal & 0x8:
                literal -= 0x10
            record.update(kind="const-int", register=register, value=literal)
        elif opcode == 0x13 and i + 1 < len(units):
            record.update(
                kind="const-int",
                register=(units[i] >> 8) & 0xFF,
                value=_signed16(units[i + 1]),
            )
        elif opcode == 0x14 and i + 2 < len(units):
            record.update(
                kind="const-int",
                register=(units[i] >> 8) & 0xFF,
                value=_signed32(units[i + 1], units[i + 2]),
            )
        elif opcode in {0x28, 0x29, 0x2A}:
            if opcode == 0x28:
                rel = (units[i] >> 8) & 0xFF
                if rel & 0x80:
                    rel -= 0x100
            elif opcode == 0x29 and i + 1 < len(units):
                rel = _signed16(units[i + 1])
            elif opcode == 0x2A and i + 2 < len(units):
                rel = _signed32(units[i + 1], units[i + 2])
            else:
                rel = 0
            record.update(kind="goto", target=i + rel)
        elif opcode in {0x2B, 0x2C} and i + 2 < len(units):
            record.update(
                kind="switch",
                register=(units[i] >> 8) & 0xFF,
                switch_kind="packed" if opcode == 0x2B else "sparse",
                cases=_switch_cases(units, i, opcode),
            )
        elif opcode == 0x22 and i + 1 < len(units):
            type_index = units[i + 1]
            if type_index < len(dex.types):
                record.update(kind="new-instance", register=(units[i] >> 8) & 0xFF, type=dex.types[type_index])
        elif opcode in {0x0A, 0x0B, 0x0C}:
            record.update(kind="move-result", register=(units[i] >> 8) & 0xFF)
        elif opcode in {0x38, 0x39} and i + 1 < len(units):
            record.update(
                kind="if-testz",
                register=(units[i] >> 8) & 0xFF,
                condition="eqz" if opcode == 0x38 else "nez",
                target=i + _signed16(units[i + 1]),
            )
        elif (0x6E <= opcode <= 0x72) or (0x74 <= opcode <= 0x78) or opcode in {0xFA, 0xFB}:
            if i + 1 < len(units):
                method_index = units[i + 1]
                if method_index < len(dex.methods):
                    record.update(
                        kind="invoke",
                        method=dex.methods[method_index].full_name,
                        registers=_invoke_registers(units, i, opcode),
                    )
        records.append(record)
        i += width
    return records


def _discover_dispatches_in_method(dex: DexFile, code: MethodCode) -> list[dict]:
    records = _decode_dispatch_records(dex, code)
    command_names = {command.lower(): command for command in COMMAND_HINTS}
    discoveries: list[dict] = []
    offset_to_pos = {record["offset"]: pos for pos, record in enumerate(records)}

    def find_concrete_task_from_switch(branch: dict) -> tuple[list[str], dict | None]:
        if branch.get("condition") == "nez":
            success_offset = branch.get("target")
        else:
            success_offset = branch.get("offset", 0) + branch.get("width", 0)
        success_pos = offset_to_pos.get(success_offset)
        if success_pos is None:
            return [], None

        discriminant = None
        discriminant_reg = None
        search_end = min(len(records), success_pos + 6)
        for k in range(success_pos, search_end):
            candidate = records[k]
            if candidate.get("kind") == "const-int":
                discriminant = candidate.get("value")
                discriminant_reg = candidate.get("register")
                break
        if not isinstance(discriminant, int) or not isinstance(discriminant_reg, int):
            return [], None

        switch_record = None
        goto_target = None
        for k in range(success_pos, search_end):
            candidate = records[k]
            if candidate.get("kind") == "goto":
                goto_target = candidate.get("target")
                break
        if isinstance(goto_target, int):
            candidate_pos = offset_to_pos.get(goto_target)
            if candidate_pos is not None and records[candidate_pos].get("kind") == "switch":
                candidate = records[candidate_pos]
                if candidate.get("register") == discriminant_reg:
                    switch_record = candidate

        if switch_record is None:
            for candidate in records[success_pos:]:
                if (
                    candidate.get("kind") == "switch"
                    and candidate.get("register") == discriminant_reg
                ):
                    switch_record = candidate
                    break
        if switch_record is None:
            return [], None

        target = switch_record.get("cases", {}).get(discriminant)
        if not isinstance(target, int):
            return [], switch_record
        target_pos = offset_to_pos.get(target)
        if target_pos is None:
            return [], switch_record

        task_types: list[str] = []
        for candidate in records[target_pos:min(len(records), target_pos + 8)]:
            if candidate.get("kind") == "new-instance":
                type_name = candidate.get("type")
                if isinstance(type_name, str):
                    task_types.append(type_name)
            if candidate.get("kind") == "goto" and candidate is not records[target_pos]:
                break
        return sorted(set(task_types)), switch_record

    for pos, record in enumerate(records):
        if record.get("kind") != "const-string":
            continue
        string_index = record.get("string_index")
        if not isinstance(string_index, int) or string_index >= len(dex.strings):
            continue
        raw_value = dex.strings[string_index]
        command = command_names.get(raw_value.lower())
        if not command:
            continue
        command_reg = record["register"]

        invoke_pos = None
        for j in range(pos + 1, min(len(records), pos + 10)):
            candidate = records[j]
            if candidate.get("kind") != "invoke":
                continue
            method = candidate.get("method", "")
            regs = candidate.get("registers", [])
            if (
                (
                    method.startswith("Ljava/lang/String;->equals(")
                    or method.startswith("Ljava/lang/String;->equalsIgnoreCase(")
                )
                and command_reg in regs
            ):
                invoke_pos = j
                break
        if invoke_pos is None:
            continue

        move_pos = invoke_pos + 1
        if move_pos >= len(records) or records[move_pos].get("kind") != "move-result":
            continue
        result_reg = records[move_pos]["register"]

        branch_pos = move_pos + 1
        if branch_pos >= len(records):
            continue
        branch = records[branch_pos]
        if branch.get("kind") != "if-testz" or branch.get("register") != result_reg:
            continue

        success_start = branch["offset"] + branch["width"]
        success_end = branch["target"] if branch["condition"] == "eqz" else None
        task_types: list[str] = []
        resolution = "direct-branch"
        switch_record = None

        if success_end is not None and success_end > success_start:
            for candidate in records:
                if not (success_start <= candidate["offset"] < success_end):
                    continue
                if candidate.get("kind") == "new-instance":
                    type_name = candidate.get("type")
                    if isinstance(type_name, str):
                        task_types.append(type_name)

        if not task_types:
            task_types, switch_record = find_concrete_task_from_switch(branch)
            if task_types:
                resolution = "string-switch"

        discoveries.append({
            "command": command,
            "dispatcher": code.method.full_name,
            "comparison": records[invoke_pos]["method"],
            "branch_condition": branch["condition"],
            "branch_target_code_unit": branch["target"],
            "task_types": sorted(set(task_types)),
            "confidence": "high" if task_types else "partial",
            "resolution": resolution if task_types else "unresolved",
            "switch_kind": switch_record.get("switch_kind") if switch_record else None,
            "evidence_note": (
                "command const-string feeds String.equals; discriminant and switch case "
                "resolve to concrete new-instance"
                if resolution == "string-switch" and task_types
                else "command const-string feeds String.equals; matching branch contains "
                     "concrete new-instance"
                if task_types
                else "command comparison identified, but concrete task construction was not resolved"
            ),
        })
    return discoveries

def _discover_task_dispatches(dexes: list[DexFile]) -> list[dict]:
    discoveries: list[dict] = []
    for dex in dexes:
        for code in dex.code.values():
            discoveries.extend(_discover_dispatches_in_method(dex, code))

    unique: dict[tuple, dict] = {}
    for item in discoveries:
        key = (
            item["command"],
            item["dispatcher"],
            tuple(item["task_types"]),
            item["branch_target_code_unit"],
        )
        unique[key] = item
    return sorted(unique.values(), key=lambda x: (x["command"], x["dispatcher"], x["task_types"]))



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
        infos = validate_apk_archive(zf)
        dex_infos = sorted(
            (
                zi for zi in infos
                if Path(zi.filename).name == "classes.dex" or (
                    Path(zi.filename).name.startswith("classes")
                    and Path(zi.filename).name.endswith(".dex")
                )
            ),
            key=lambda zi: zi.filename,
        )
        dex_total = sum(zi.file_size for zi in dex_infos)
        if dex_total > 512 * 1024 * 1024:
            raise DexError(f"DEX payload exceeds analysis budget: {dex_total} bytes")
        for zi in dex_infos:
            if zi.file_size > MAX_ENTRY_UNCOMPRESSED:
                raise DexError(f"{zi.filename}: DEX exceeds per-entry budget")
            dexes.append(DexFile(zf.read(zi), zi.filename))

    # DEX method indexes are local to each file. Canonicalize by full Dalvik
    # signature so a call reference in classes.dex can connect to an
    # implementation that lives in classes2.dex.
    graph: dict[str, set[str]] = {}
    code_records: list[tuple[DexFile, MethodCode]] = []
    unique_method_refs: set[str] = set()
    supertypes: dict[str, set[str]] = {}

    for dex in dexes:
        for owner, parents in dex.class_supertypes.items():
            supertypes.setdefault(owner, set()).update(parents)
        unique_method_refs.update(method.full_name for method in dex.methods)
        for local_idx, code in dex.code.items():
            caller = code.method.full_name
            graph.setdefault(caller, set())
            for callee_idx in code.calls:
                if callee_idx < len(dex.methods):
                    graph[caller].add(dex.methods[callee_idx].full_name)
            code_records.append((dex, code))

    code_method_names = {code.method.full_name for _, code in code_records}
    polymorphic_edges_added = _add_polymorphic_edges(
        graph,
        code_method_names,
        supertypes,
    )
    runnable_dispatch_edges = _add_runnable_dispatch_edges(
        graph, code_records, code_method_names, supertypes
    )
    task_dispatches = _discover_task_dispatches(dexes)

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

    task_execute_paths: list[dict] = []
    for dispatch in task_dispatches:
        for task_type in dispatch["task_types"]:
            execute_candidates = sorted(
                full for full in code_method_names
                if full.startswith(task_type + "->execute(") or full.startswith(task_type + "->run(")
            )
            for execute_method in execute_candidates:
                task_execute_paths.append({
                    "command": dispatch["command"],
                    "dispatcher": dispatch["dispatcher"],
                    "task_type": task_type,
                    "entry_method": execute_method,
                    "sink_paths": _shortest_paths(execute_method, graph, max_depth),
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
        "polymorphic_edges_added": polymorphic_edges_added,
        "runnable_dispatch_edges_added": len(runnable_dispatch_edges),
        "runnable_dispatch_edges": runnable_dispatch_edges,
        "first_party_prefixes": list(first_party_prefixes),
        "evidence_semantics": {
            "call_edge": "STATIC_CONFIRMED invocation reference; does not prove runtime execution",
            "command_seed": "method contains an exact const-string command identifier",
            "sink_path": "shortest static invoke path from command-seed method to privileged sink",
            "cross_dex": "method references are canonicalized by full Dalvik signature across DEX files",
            "polymorphic_dispatch": "known app class/interface relationships add synthetic static dispatch edges",
            "runnable_dispatch": "concrete same-method Runnable allocation passed to a scheduling API adds a static edge to that concrete run() implementation",
            "task_dispatch": "high-confidence mappings resolve either a direct equals branch or a two-stage Java/D8 string-switch to a concrete new-instance",
        },
        "task_dispatches": task_dispatches,
        "task_execute_paths": task_execute_paths,
        "command_paths": command_paths,
        "sink_callers": sorted(sink_callers, key=lambda x: (x["sink"], x["caller"])),
    }

