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


def _signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


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
                (method.startswith("Ljava/lang/String;->equals(") or
                 method.startswith("Ljava/lang/String;->equalsIgnoreCase("))
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

        if success_end is not None and success_end > success_start:
            for candidate in records:
                if not (success_start <= candidate["offset"] < success_end):
                    continue
                if candidate.get("kind") == "new-instance":
                    type_name = candidate.get("type")
                    if isinstance(type_name, str):
                        task_types.append(type_name)

        discoveries.append({
            "command": command,
            "dispatcher": code.method.full_name,
            "comparison": records[invoke_pos]["method"],
            "branch_condition": branch["condition"],
            "branch_target_code_unit": branch["target"],
            "task_types": sorted(set(task_types)),
            "confidence": "high" if task_types else "partial",
            "evidence_note": (
                "command const-string feeds String.equals; matching branch contains concrete new-instance"
                if task_types else
                "command comparison identified, but concrete task construction was not resolved"
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

    polymorphic_edges_added = _add_polymorphic_edges(
        graph,
        {code.method.full_name for _, code in code_records},
        supertypes,
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
    code_method_names = {code.method.full_name for _, code in code_records}
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
        "first_party_prefixes": list(first_party_prefixes),
        "evidence_semantics": {
            "call_edge": "STATIC_CONFIRMED invocation reference; does not prove runtime execution",
            "command_seed": "method contains an exact const-string command identifier",
            "sink_path": "shortest static invoke path from command-seed method to privileged sink",
            "cross_dex": "method references are canonicalized by full Dalvik signature across DEX files",
            "polymorphic_dispatch": "known app class/interface relationships add synthetic static dispatch edges",
            "task_dispatch": "high-confidence mappings require const-string -> String.equals -> matching branch -> concrete new-instance",
        },
        "task_dispatches": task_dispatches,
        "task_execute_paths": task_execute_paths,
        "command_paths": command_paths,
        "sink_callers": sorted(sink_callers, key=lambda x: (x["sink"], x["caller"])),
    }

