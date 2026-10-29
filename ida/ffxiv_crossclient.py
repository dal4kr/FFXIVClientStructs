from __future__ import annotations

import argparse
import bisect
import copy
import hashlib
import json
import re
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import capstone
import pefile
import yaml


def describe_code(image, decoder, start, code, end, prefix=False):
    normalized = bytearray(code)
    references = []
    regions = []
    consumed = 0
    for instruction in decoder.disasm(code, start):
        consumed += instruction.size
        offset = instruction.address - start
        for operand in instruction.operands:
            target = None
            if (
                operand.type == capstone.x86.X86_OP_MEM
                and operand.mem.base == capstone.x86.X86_REG_RIP
            ):
                target = instruction.address + instruction.size + operand.mem.disp
                begin, size = offset + instruction.disp_offset, instruction.disp_size
            elif operand.type == capstone.x86.X86_OP_IMM:
                if instruction.group(capstone.CS_GRP_CALL) or instruction.group(
                    capstone.CS_GRP_JUMP
                ):
                    target = operand.imm
                    if start <= target < end:
                        continue
                elif image.base <= operand.imm < image.base + image.size:
                    target = operand.imm - image.base
                if target is None:
                    continue
                begin, size = offset + instruction.imm_offset, instruction.imm_size
            else:
                continue
            normalized[begin : begin + size] = bytes(size)
            regions.append((begin, size))
            if 0 <= target < image.size:
                references.append((offset, target))
        if prefix and (
            instruction.group(capstone.CS_GRP_RET)
            or instruction.id == capstone.x86.X86_INS_JMP
        ):
            break
    return bytes(normalized[:consumed]), tuple(references), regions, consumed


@dataclass(slots=True)
class Function:
    start: int
    end: int
    digest: bytes = b""
    references: tuple = ()


class Image:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("仅支持 x64 PE 客户端")
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.sections = tuple(self.pe.sections)
        self.contents = {
            section.VirtualAddress: self.raw[
                section.PointerToRawData : section.PointerToRawData
                + section.SizeOfRawData
            ]
            for section in self.sections
        }
        self.pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
        )
        self.functions = {
            entry.struct.BeginAddress: Function(
                entry.struct.BeginAddress, entry.struct.EndAddress
            )
            for entry in self.pe.DIRECTORY_ENTRY_EXCEPTION
            if entry.struct.BeginAddress < entry.struct.EndAddress
        }
        self.starts = sorted(self.functions)

    def section(self, rva):
        return next(
            (
                s
                for s in self.sections
                if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize
            ),
            None,
        )

    def read(self, rva, size):
        section = self.section(rva)
        if (
            section is None
            or rva + size > section.VirtualAddress + section.SizeOfRawData
        ):
            return b""
        offset = rva - section.VirtualAddress
        return self.contents[section.VirtualAddress][offset : offset + size]

    def executable(self, rva):
        section = self.section(rva)
        return section is not None and bool(section.Characteristics & 0x20000000)

    def function(self, rva):
        index = bisect.bisect_right(self.starts, rva) - 1
        if index < 0:
            return None
        function = self.functions[self.starts[index]]
        return function if rva < function.end else None

    def index(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        groups = defaultdict(list)
        for function in self.functions.values():
            code = self.read(function.start, function.end - function.start)
            normalized, references, _, decoded_size = describe_code(
                self, decoder, function.start, code, function.end
            )
            if decoded_size != len(code):
                continue
            function.digest = hashlib.blake2b(normalized, digest_size=16).digest()
            function.references = references
            groups[(len(code), function.digest)].append(function.start)
        return groups


@dataclass
class Mapping:
    source: Image
    target: Image
    addresses: dict = field(default_factory=dict)
    reasons: dict = field(default_factory=dict)
    conflicts: set = field(default_factory=set)
    spans: dict = field(default_factory=dict)
    data_sha256: str = ""
    structs_sha256: str = ""
    symbols: dict = field(default_factory=dict)
    reference_symbols: dict = field(default_factory=dict)

    def add(self, source, target, reason):
        if source in self.conflicts:
            return False
        if source in self.addresses:
            if self.addresses[source] != target:
                self.conflicts.add(source)
                self.addresses.pop(source)
                self.reasons.pop(source)
            return False
        if self.source.section(source) is None or self.target.section(target) is None:
            return False
        if self.source.executable(source) != self.target.executable(target):
            return False
        self.addresses[source] = target
        self.reasons[source] = reason
        return True

    def resolve(self, source):
        if source in self.conflicts:
            return None
        if source in self.addresses:
            return self.addresses[source]
        function = self.source.function(source)
        if function is not None and function.start in self.conflicts:
            return None
        if function is not None and function.start in self.spans:
            target, length = self.spans[function.start]
            if source < function.start + length:
                return target + source - function.start
        if function is None or function.start not in self.addresses:
            return None
        target = self.target.functions.get(self.addresses[function.start])
        if target is None or not function.digest or function.digest != target.digest:
            return None
        if function.end - function.start != target.end - target.start:
            return None
        return target.start + source - function.start

    def match(self, data):
        if self.source.sha256 == self.target.sha256:
            for category in ("globals", "functions"):
                for address in data.get(category, {}) or {}:
                    self.add(
                        address - self.source.base,
                        address - self.source.base,
                        "identical-image",
                    )
            for definition in data.get("classes", {}).values():
                if not definition:
                    continue
                for address in definition.get("funcs", {}) or {}:
                    self.add(
                        address - self.source.base,
                        address - self.source.base,
                        "identical-image",
                    )
                for category in ("instances", "vtbls"):
                    for item in definition.get(category, []) or []:
                        if item["ea"]:
                            self.add(
                                item["ea"] - self.source.base,
                                item["ea"] - self.source.base,
                                "identical-image",
                            )
            return self
        print("正在建立参考客户端函数索引", flush=True)
        source_groups = self.source.index()
        print("正在建立目标客户端函数索引", flush=True)
        target_groups = self.target.index()
        pairs = []
        for key, starts in source_groups.items():
            targets = target_groups.get(key, [])
            if len(starts) == len(targets) == 1:
                source, target = starts[0], targets[0]
                self.add(source, target, "normalized-function")
                self.spans[source] = (target, key[0])
                pairs.append((source, target))
        print(f"已匹配 {len(pairs)} 个唯一函数，正在迁移引用关系", flush=True)
        votes = defaultdict(Counter)
        for source, target in pairs:
            left = self.source.functions[source].references
            right = self.target.functions[target].references
            if len(left) != len(right):
                continue
            for (offset, address), (target_offset, target_address) in zip(left, right):
                if offset == target_offset:
                    votes[address][target_address] += 1
        for source, candidates in votes.items():
            if len(candidates) == 1:
                target = next(iter(candidates))
                if self.source.executable(source):
                    source_function = self.source.functions.get(source)
                    target_function = self.target.functions.get(target)
                    if (
                        source_function
                        and target_function
                        and source_function.digest != target_function.digest
                    ):
                        continue
                self.add(source, target, "matched-reference")
        self.refine_functions(source_groups, target_groups)
        self.match_named_functions(data)
        self.match_vtables(data)
        self.match_constants(data)
        return self

    def match_named_functions(self, data):
        addresses = set(data.get("functions", {}) or {})
        for definition in data.get("classes", {}).values():
            if definition:
                addresses.update(definition.get("funcs", {}) or {})
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        for address in sorted(addresses):
            source = address - self.source.base
            if self.resolve(source) is not None or not self.source.executable(source):
                continue
            function = self.source.function(source)
            if function is not None and source != function.start:
                continue
            end = min(function.end, source + 128) if function else source + 128
            code = self.source.read(source, end - source)
            _, references, regions, consumed = describe_code(
                self.source, decoder, source, code, end, prefix=True
            )
            if consumed < 8:
                continue
            mask = bytearray(b"\xff" * consumed)
            for begin, size in regions:
                mask[begin : begin + size] = bytes(size)
            matches = []
            for image in (self.source, self.target):
                candidates = find_masked(
                    image, code[:consumed], bytes(mask), executable=True
                )
                matches.append(candidates)
            if matches[0] != [source] or len(matches[1]) != 1:
                continue
            target = matches[1][0]
            target_function = self.target.function(target)
            if target_function is not None and target_function.start != target:
                continue
            if not self.add(source, target, "unique-function-prefix"):
                continue
            target_code = self.target.read(target, consumed)
            _, target_references, _, _ = describe_code(
                self.target,
                decoder,
                target,
                target_code,
                target + consumed,
                prefix=True,
            )
            for (offset, reference), (right_offset, right_reference) in zip(
                references, target_references
            ):
                if offset == right_offset:
                    self.add(reference, right_reference, "unique-function-reference")

    def refine_functions(self, source_groups, target_groups):
        for _ in range(4):
            added = 0
            for key, starts in source_groups.items():
                targets = target_groups.get(key, [])
                if not targets:
                    continue
                for source in starts:
                    if source in self.addresses or source in self.conflicts:
                        continue
                    known = [
                        (offset, self.resolve(address))
                        for offset, address in self.source.functions[source].references
                    ]
                    known = [
                        (offset, address)
                        for offset, address in known
                        if address is not None
                    ]
                    if not known:
                        continue
                    candidates = []
                    for target in targets:
                        references = dict(self.target.functions[target].references)
                        if all(
                            references.get(offset) == address
                            for offset, address in known
                        ):
                            candidates.append(target)
                    if len(candidates) == 1 and self.add(
                        source, candidates[0], "function-reference-graph"
                    ):
                        target = candidates[0]
                        self.spans[source] = (target, key[0])
                        added += 1
                        for (offset, address), (right_offset, right_address) in zip(
                            self.source.functions[source].references,
                            self.target.functions[target].references,
                        ):
                            if offset == right_offset:
                                self.add(
                                    address, right_address, "function-reference-graph"
                                )
            if not added:
                break

    def match_vtables(self, data):
        target_slots = defaultdict(list)
        for section in self.target.sections:
            if (
                section.Characteristics & 0x20000000
                or section.Characteristics & 0x80000000
            ):
                continue
            raw = self.target.read(section.VirtualAddress, section.SizeOfRawData)
            for offset in range(0, len(raw) - 7, 8):
                pointer = struct.unpack_from("<Q", raw, offset)[0] - self.target.base
                if self.target.executable(pointer):
                    target_slots[pointer].append(section.VirtualAddress + offset)
        for definition in data.get("classes", {}).values():
            if not definition:
                continue
            for table in definition.get("vtbls", []) or []:
                source = table["ea"] - self.source.base
                if source in self.addresses or table["ea"] == 0:
                    continue
                pointers = []
                for slot in range(min(table.get("size") or 64, 64)):
                    raw = self.source.read(source + slot * 8, 8)
                    if len(raw) != 8:
                        break
                    pointer = struct.unpack("<Q", raw)[0] - self.source.base
                    if not self.source.executable(pointer):
                        break
                    pointers.append(pointer)
                candidates = Counter()
                known = []
                for slot, pointer in enumerate(pointers):
                    target = self.resolve(pointer)
                    if target is None:
                        continue
                    known.append((slot, target))
                    for location in target_slots[target]:
                        candidates[location - slot * 8] += 1
                if len({pointer for _, pointer in known}) < 2:
                    continue
                valid = [
                    target
                    for target, votes in candidates.items()
                    if votes == len(known) and self.target.section(target) is not None
                ]
                if len(valid) == 1:
                    self.add(source, valid[0], "vtable-function-slots")

    def match_constants(self, data):
        for source in data.get("globals") or {}:
            rva = source - self.source.base
            if self.resolve(rva) is not None:
                continue
            pattern = self.source.read(rva, 64)
            if len(pattern) != 64 or len(set(pattern)) < 12:
                continue
            source_section = self.source.section(rva)
            source_raw = self.source.contents[source_section.VirtualAddress]
            first = source_raw.find(pattern)
            if source_raw.find(pattern, first + 1) >= 0:
                continue
            candidates = []
            for section in self.target.sections:
                if (
                    section.Name != source_section.Name
                    or section.Characteristics & 0x20000000
                ):
                    continue
                raw = self.target.read(section.VirtualAddress, section.SizeOfRawData)
                location = raw.find(pattern)
                while location >= 0 and len(candidates) < 2:
                    candidates.append(section.VirtualAddress + location)
                    location = raw.find(pattern, location + 1)
            if len(candidates) == 1:
                self.add(rva, candidates[0], "constant-data")

    def payload(self):
        return {
            "schema": 5,
            "source_sha256": self.source.sha256,
            "target_sha256": self.target.sha256,
            "source_base": self.source.base,
            "target_base": self.target.base,
            "addresses": {str(k): v for k, v in sorted(self.addresses.items())},
            "reasons": {str(k): v for k, v in sorted(self.reasons.items())},
            "conflicts": sorted(self.conflicts),
            "spans": {str(k): v for k, v in sorted(self.spans.items())},
            "data_sha256": self.data_sha256,
            "structs_sha256": self.structs_sha256,
            "symbols": self.symbols,
            "reference_symbols": self.reference_symbols,
        }

    def load(self, payload):
        if (
            payload.get("schema") != 5
            or payload.get("source_sha256") != self.source.sha256
            or payload.get("target_sha256") != self.target.sha256
        ):
            raise ValueError("地址映射与指定客户端文件不匹配")
        self.addresses = {int(k): v for k, v in payload["addresses"].items()}
        self.reasons = {int(k): v for k, v in payload["reasons"].items()}
        self.conflicts = set(payload["conflicts"])
        self.spans = {int(k): tuple(v) for k, v in payload["spans"].items()}
        self.data_sha256 = payload["data_sha256"]
        self.structs_sha256 = payload["structs_sha256"]
        self.symbols = payload["symbols"]
        self.reference_symbols = payload["reference_symbols"]


def relocate_data(data, mapping):
    result = {
        "version": data.get("version"),
        "globals": {},
        "functions": {},
        "classes": {},
        "_crossclient": {
            "source_sha256": mapping.source.sha256,
            "target_sha256": mapping.target.sha256,
            "image_base": mapping.target.base,
        },
    }
    unresolved = []
    resolved = Counter()

    def address(value, kind, name):
        if value == 0:
            return 0
        rva = value - mapping.source.base
        target = mapping.resolve(rva)
        if target is None:
            unresolved.append({"kind": kind, "name": name, "source": value})
            return None
        resolved[kind] += 1
        return mapping.target.base + target

    for category in ("globals", "functions"):
        for value, name in (data.get(category) or {}).items():
            target = address(value, category, name)
            if target is not None:
                result[category][target] = name
    for name, definition in data.get("classes", {}).items():
        if not definition:
            result["classes"][name] = definition
            continue
        cls = {
            key: value
            for key, value in definition.items()
            if key not in ("funcs", "vtbls", "instances")
        }
        if "funcs" in definition:
            cls["funcs"] = {}
            for value, function in (definition["funcs"] or {}).items():
                target = address(value, "member_functions", f"{name}.{function}")
                if target is not None:
                    cls["funcs"][target] = function
        for category in ("vtbls", "instances"):
            if definition.get(category) is None:
                continue
            cls[category] = []
            for item in definition[category]:
                target = address(item["ea"], category, name)
                if target is not None:
                    cls[category].append({**item, "ea": target})
        result["classes"][name] = cls
    report = {
        "source_sha256": mapping.source.sha256,
        "target_sha256": mapping.target.sha256,
        "resolved": dict(resolved),
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
        "conflict_count": len(mapping.conflicts),
    }
    return result, report


def write_json(path, value):
    with Path(path).open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def find_masked(image, pattern, mask, executable=True):
    runs = []
    start = None
    for index, byte in enumerate(mask + b"\x00"):
        if byte and start is None:
            start = index
        elif not byte and start is not None:
            runs.append((start, index))
            start = None
    if not runs:
        return []
    begin, end = max(runs, key=lambda run: run[1] - run[0])
    anchor = pattern[begin:end]
    if len(anchor) < 3:
        return []
    matches = []
    matcher = re.compile(
        b"".join(
            re.escape(bytes([value])) if selected else b"."
            for value, selected in zip(pattern, mask)
        ),
        re.DOTALL,
    )
    for section in image.sections:
        if executable != bool(section.Characteristics & 0x20000000):
            continue
        raw = image.read(section.VirtualAddress, section.SizeOfRawData)
        offset = raw.find(anchor)
        while offset >= 0:
            location = offset - begin
            if 0 <= location <= len(raw) - len(pattern) and matcher.match(
                raw, location
            ):
                matches.append(section.VirtualAddress + location)
                if len(matches) == 2:
                    return matches
            offset = raw.find(anchor, offset + 1)
    return matches


def resolve_symbols(structures, image):
    resolved = {}
    statics = {}
    unresolved = []
    data = {
        "globals": {},
        "functions": {},
        "classes": {},
        "_crossclient": {"target_sha256": image.sha256, "image_base": image.base},
    }
    signatures = {
        item["signature"]
        for definition in structures
        for category in (
            "member_functions",
            "static_member_functions",
            "static_members",
        )
        for item in definition.get(category, [])
    }
    signatures.update(
        definition["vtable_signature"]["signature"]
        for definition in structures
        if "vtable_signature" in definition
    )
    for signature in sorted(signatures):
        tokens = signature.split()
        if not tokens or any(
            token != "??" and re.fullmatch("[0-9A-Fa-f]{2}", token) is None
            for token in tokens
        ):
            raise ValueError("特征码格式无效")
        pattern = bytes(0 if token == "??" else int(token, 16) for token in tokens)
        mask = bytes(0 if token == "??" else 255 for token in tokens)
        matches = find_masked(image, pattern, mask)
        if len(matches) != 1:
            continue
        match = matches[0]
        address = match
        if pattern[0] in (0xE8, 0xE9):
            address = (
                match
                + 5
                + int.from_bytes(image.read(match + 1, 4), "little", signed=True)
            )
        function = image.function(address)
        resolved[signature] = {
            "match": image.base + match,
            "address": image.base + address,
            "function": image.executable(address)
            and (function is None or function.start == address),
        }

    def follow(signature, offsets):
        address = resolved[signature]["match"] - image.base
        for offset in offsets:
            displacement = image.read(address + offset, 4)
            if len(displacement) != 4:
                raise ValueError("相对地址超出客户端映像")
            address += offset + 4 + int.from_bytes(displacement, "little", signed=True)
        if image.section(address) is None:
            raise ValueError("解析结果超出客户端映像")
        return image.base + address

    for definition in structures:
        cls = {
            "funcs": {},
            "instances": [],
            "vtbls": [],
            "vfuncs": {
                member["offset"] // 8: member["name"]
                for member in definition.get("virtual_functions", [])
            },
        }
        for category in (
            "member_functions",
            "static_member_functions",
            "static_members",
        ):
            for member in definition.get(category, []):
                signature = member["signature"]
                if signature not in resolved or (
                    category != "static_members" and not resolved[signature]["function"]
                ):
                    unresolved.append(
                        {
                            "type": definition["type"],
                            "name": member["name"],
                            "kind": category,
                        }
                    )
                    continue
                if category == "static_members":
                    address = follow(signature, member["relative_follow_offsets"])
                    key = (
                        signature
                        + "|"
                        + ",".join(map(str, member["relative_follow_offsets"]))
                    )
                    statics[key] = address
                    cls["instances"].append(
                        {
                            "ea": address,
                            "name": member["name"],
                            "pointer": member["is_pointer"],
                        }
                    )
                else:
                    cls["funcs"][resolved[signature]["address"]] = member["name"]
        if "vtable_signature" in definition:
            table = definition["vtable_signature"]
            if table["signature"] in resolved:
                cls["vtbls"].append(
                    {"ea": follow(table["signature"], table["relative_follow_offsets"])}
                )
            else:
                unresolved.append(
                    {"type": definition["type"], "name": "虚表", "kind": "vtbls"}
                )
        if any(cls.values()):
            data["classes"][definition["type"]] = cls
    return {
        "resolved_signatures": resolved,
        "resolved_statics": statics,
        "unresolved": unresolved,
        "data": data,
        "target_sha256": image.sha256,
        "image_base": image.base,
    }


def recover_declared(mapping, data, structures):
    for definition in structures:
        original = (data.get("classes", {}).get(definition["type"]) or {}).get(
            "funcs"
        ) or {}
        for category in ("member_functions", "static_member_functions"):
            for member in definition.get(category, []):
                signature = member["signature"]
                source = mapping.reference_symbols["resolved_signatures"].get(signature)
                target = mapping.symbols["resolved_signatures"].get(signature)
                if (
                    source is None
                    or target is None
                    or not source["function"]
                    or not target["function"]
                    or original.get(source["address"]) != member["name"]
                    or mapping.resolve(source["address"] - mapping.source.base)
                    is not None
                ):
                    continue
                mapping.add(
                    source["address"] - mapping.source.base,
                    target["address"] - mapping.target.base,
                    "declared-signature",
                )


def validate_declared(mapping, structures):
    disagreements = list(mapping.symbols.setdefault("mapping_disagreements", []))
    for signature, source in mapping.reference_symbols["resolved_signatures"].items():
        target = mapping.symbols["resolved_signatures"].get(signature)
        if not source["function"] or target is None or not target["function"]:
            continue
        rva = source["address"] - mapping.source.base
        address = mapping.resolve(rva)
        target_rva = target["address"] - mapping.target.base
        if address is not None and address != target_rva:
            disagreements.append(
                {
                    "source": source["address"],
                    "binary_target": mapping.target.base + address,
                    "signature_target": target["address"],
                }
            )
            mapping.add(rva, target_rva, "signature-disagreement")
    mapping.symbols["mapping_disagreements"] = disagreements
    for definition in structures:
        for category in ("member_functions", "static_member_functions"):
            for member in definition.get(category, []):
                signature = member["signature"]
                source = mapping.reference_symbols["resolved_signatures"].get(signature)
                target = mapping.symbols["resolved_signatures"].get(signature)
                if (
                    source is None
                    or target is None
                    or source["address"] - mapping.source.base not in mapping.conflicts
                ):
                    continue
                target["function"] = False
                native = mapping.symbols["data"]["classes"].get(definition["type"])
                if native is not None:
                    native["funcs"] = {
                        address: name
                        for address, name in native["funcs"].items()
                        if int(address) != target["address"]
                    }
                unresolved = {
                    "type": definition["type"],
                    "name": member["name"],
                    "kind": category,
                    "reason": "binary-signature-disagreement",
                }
                if unresolved not in mapping.symbols["unresolved"]:
                    mapping.symbols["unresolved"].append(unresolved)


def main():
    parser = argparse.ArgumentParser(description="从参考客户端自动迁移 FFCS 命名地址")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument(
        "--data", type=Path, default=Path(__file__).with_name("data.yml")
    )
    parser.add_argument(
        "--structs", type=Path, default=Path(__file__).with_name("ffxiv_structs.yml")
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mapping", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    inputs = {
        args.source.resolve(),
        args.target.resolve(),
        args.data.resolve(),
        args.structs.resolve(),
    }
    outputs = [args.output.resolve(), args.mapping.resolve(), args.report.resolve()]
    if len(set(outputs)) != 3 or inputs.intersection(outputs):
        parser.error("输出路径必须互不相同，且不得覆盖客户端或上游数据")
    started = time.monotonic()
    data_raw = args.data.read_bytes()
    data_sha256 = hashlib.sha256(data_raw).hexdigest()
    data = yaml.load(data_raw.decode("utf-8"), Loader=yaml.CSafeLoader)
    mapping = Mapping(Image(args.source), Image(args.target))
    changed = True
    if args.mapping.exists():
        mapping.load(json.loads(args.mapping.read_text(encoding="utf-8")))
        changed = mapping.data_sha256 != data_sha256
        if mapping.data_sha256 != data_sha256:
            mapping.match_named_functions(data)
            mapping.match_vtables(data)
            mapping.match_constants(data)
    else:
        mapping.match(data)
    mapping.data_sha256 = data_sha256
    write_json(args.mapping, mapping.payload())
    structs_raw = args.structs.read_bytes()
    structs_sha256 = hashlib.sha256(structs_raw).hexdigest()
    structures = yaml.load(structs_raw.decode("utf-8"), Loader=yaml.CSafeLoader)[
        "structs"
    ]
    if mapping.structs_sha256 != structs_sha256:
        print("正在解析当前客户端的 C# 原生声明", flush=True)
        mapping.symbols = resolve_symbols(structures, mapping.target)
        mapping.structs_sha256 = structs_sha256
        changed = True
        write_json(args.mapping, mapping.payload())
    if mapping.reference_symbols.get("structs_sha256") != structs_sha256:
        print("正在核对参考客户端的 C# 原生声明", flush=True)
        if mapping.source.sha256 == mapping.target.sha256:
            mapping.reference_symbols = copy.deepcopy(mapping.symbols)
        else:
            mapping.reference_symbols = resolve_symbols(structures, mapping.source)
        mapping.reference_symbols["structs_sha256"] = structs_sha256
        changed = True
    if changed:
        recover_declared(mapping, data, structures)
    write_json(args.mapping, mapping.payload())
    mapping = Mapping(
        mapping.source,
        mapping.target,
        addresses=mapping.addresses.copy(),
        reasons=mapping.reasons.copy(),
        conflicts=mapping.conflicts.copy(),
        spans=mapping.spans.copy(),
        symbols=copy.deepcopy(mapping.symbols),
        reference_symbols=mapping.reference_symbols,
    )
    validate_declared(mapping, structures)
    relocated, report = relocate_data(data, mapping)
    for name, definition in mapping.symbols["data"]["classes"].items():
        existing = relocated["classes"].setdefault(name, {}) or {}
        for category in ("funcs", "vfuncs"):
            destination = existing.setdefault(category, {})
            for key, value in definition.get(category, {}).items():
                if category == "funcs" and value in destination.values():
                    continue
                destination.setdefault(int(key), value)
        if not existing.get("instances") and definition["instances"]:
            existing["instances"] = definition["instances"]
        relocated["classes"][name] = existing
    relocated["_crossclient"].update(
        {
            key: mapping.symbols[key]
            for key in ("resolved_signatures", "resolved_statics")
        }
    )
    report["native_unresolved"] = mapping.symbols["unresolved"]
    report["signature_disagreements"] = mapping.symbols["mapping_disagreements"]
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        yaml.safe_dump(relocated, stream, allow_unicode=True, sort_keys=False)
    write_json(args.report, report)
    print(
        json.dumps(
            {
                "resolved": report["resolved"],
                "unresolved": report["unresolved_count"],
                "seconds": round(time.monotonic() - started, 2),
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
