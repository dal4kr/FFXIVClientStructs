from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from collections import Counter, defaultdict, deque
from functools import lru_cache
from pathlib import Path

import capstone
import yaml
from ahocorasick_rs import BytesAhoCorasick

from ffxiv_crossclient import Image, Mapping, find_masked, write_json


def source_files(roots):
    for root in roots:
        root = root.resolve()
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--", "*.cs"],
            check=True, capture_output=True,
        )
        for relative in result.stdout.decode("utf-8").split("\0"):
            if relative and not {"obj", "bin"}.intersection(Path(relative).parts):
                yield root / relative


def declarations(roots, contents=None):
    structures = []
    signatures = []
    for path in source_files(roots):
        raw = contents[str(path)] if contents is not None else path.read_bytes()
        text = raw.decode("utf-8-sig")
        masked = re.sub(
            r'//[^\n]*|/\*[\s\S]*?\*/|@?"(?:""|\\.|[^"\\])*"',
            lambda match: " " * len(match[0]), text,
        )
        comments = [
            (match.start(), match.end())
            for match in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|@?"(?:""|\\.|[^"\\])*"', text)
            if match[0].startswith(("//", "/*"))
        ]
        depth = [0]
        for character in masked:
            depth.append(depth[-1] + (character == "{") - (character == "}"))
        spans = []
        for match in re.finditer(r"\bstruct\s+(\w+)[^{;]*\{", masked):
            begin = match.end()
            end = begin
            while end < len(masked) and depth[end] >= depth[begin]:
                end += 1
            spans.append((match, begin, end))
        namespace = re.search(r"\bnamespace\s+([\w.]+)", masked)
        for match, begin, end in spans:
            owners = [item[0][1] for item in spans if item[1] < match.start() < item[2]]
            native = namespace[1] if namespace else ""
            native = re.sub(r"^FFXIVClientStructs(?:\.Expansion)?\.FFXIV\.", "", native)
            native = "::".join([*native.split("."), *owners, match[1]])
            preceding = text[max(0, text.rfind("}", 0, match.start()) + 1):match.start()]
            layouts = list(re.finditer(r"StructLayout\([^\]]*?Size\s*=\s*(0x[\da-fA-F]+|\d+)", preceding))
            if not layouts:
                continue
            size = layouts[-1]
            size_start = match.start() - len(preceding) + size.start(1)
            definition = {
                "type": native, "path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                "size": int(size[1], 0), "size_span": [size_start, size_start + len(size[1])],
                "fields": [], "methods": [], "virtuals": [],
            }
            body = text[begin:end]
            for field in re.finditer(
                r"\[FieldOffset\(\s*(0x[\da-fA-F]+|\d+)\s*\)\][^;{}]*?\b(\w+)\s*(?:;|=>)", body,
            ):
                if depth[begin + field.start()] != depth[begin] or masked[begin + field.start()] != "[":
                    continue
                definition["fields"].append({
                    "name": field[2], "offset": int(field[1], 0),
                    "span": [begin + field.start(1), begin + field.end(1)],
                })
            for method in re.finditer(
                r'\[MemberFunction\s*\(\s*"([\da-fA-F? ]+)"\s*\)\s*\]([\s\S]*?)\bpartial\s+[\w<>.*]+\s+(\w+)\s*\(', body,
            ):
                if depth[begin + method.start()] == depth[begin] and masked[begin + method.start()] == "[":
                    definition["methods"].append({
                        "name": method[3], "signature": method[1],
                        "instance": not re.search(r"\bstatic\b", method[2]),
                    })
            for method in re.finditer(
                r'\[VirtualFunction\s*\(\s*(0x[\da-fA-F]+|\d+)\s*\)\s*\][\s\S]*?\bpartial\s+[\w<>.*]+\s+(\w+)\s*\(', body,
            ):
                if depth[begin + method.start()] == depth[begin] and masked[begin + method.start()] == "[":
                    definition["virtuals"].append({
                        "name": method[2], "slot": int(method[1], 0),
                        "span": [begin + method.start(1), begin + method.end(1)],
                    })
            structures.append(definition)
        for match in re.finditer(r'"((?:[\da-fA-F]{2}|\?{1,2})(?:\s+(?:[\da-fA-F]{2}|\?{1,2})){3,})"', text):
            if any(begin <= match.start() < end for begin, end in comments):
                continue
            attribute = re.search(r"\[\s*(MemberFunction|StaticAddress|VirtualTable)\s*\(\s*$", text[:match.start()])
            signatures.append({
                "path": str(path), "line": text.count("\n", 0, match.start()) + 1,
                "signature": match[1], "span": [match.start(1), match.end(1)],
                "sha256": hashlib.sha256(raw).hexdigest(),
                "kind": attribute[1] if attribute else "raw",
            })
    return structures, signatures


def revision_contents(root, revision):
    repository = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()
    files = list(source_files([root]))
    requests = [f"{revision}:{path.relative_to(Path(repository)).as_posix()}" for path in files]
    result = subprocess.run(
        ["git", "-C", repository, "cat-file", "--batch"],
        input=("\n".join(requests) + "\n").encode("utf-8"), check=True, capture_output=True,
    )
    offset = 0
    contents = {}
    for path in files:
        end = result.stdout.index(b"\n", offset)
        header = result.stdout[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise ValueError(f"指定基线不存在源码文件：{path}")
        size = int(header[2])
        contents[str(path)] = result.stdout[end + 1:end + 1 + size]
        offset = end + 2 + size
    return contents


def locate(image, signature):
    tokens = signature.split()
    pattern = bytes(0 if "?" in token else int(token, 16) for token in tokens)
    mask = bytes(0 if "?" in token else 255 for token in tokens)
    matches = find_masked(image, pattern, mask)
    address = matches[0] if len(matches) == 1 else None
    if address is not None and pattern[0] in (0xE8, 0xE9):
        address += 5 + int.from_bytes(image.read(address + 1, 4), "little", signed=True)
    return {"matches": matches, "address": address}


def resolve_many(images, signatures, deadline):
    patterns = {}
    anchors = defaultdict(list)
    for signature in sorted(signatures):
        tokens = signature.split()
        pattern = bytes(0 if "?" in token else int(token, 16) for token in tokens)
        runs = list(re.finditer(rb"[^\x00]+", bytes(0 if "?" in token else 255 for token in tokens)))
        if not runs:
            raise ValueError("特征码不能完全由通配符组成")
        run = max(runs, key=lambda item: item.end() - item.start())
        anchor = pattern[run.start():run.end()]
        anchors[anchor].append((signature, run.start()))
        patterns[signature] = re.compile(b"".join(
            b"." if "?" in token else re.escape(bytes([int(token, 16)])) for token in tokens
        ), re.DOTALL)
    keys = list(anchors)
    automaton = BytesAhoCorasick(keys)
    resolutions = {signature: [] for signature in signatures}
    for image in images:
        matches = {signature: [] for signature in signatures}
        for section in image.sections:
            if not section.Characteristics & 0x20000000:
                continue
            raw = image.contents[section.VirtualAddress]
            for anchor_index, begin, _ in automaton.find_matches_as_indexes(raw, overlapping=True):
                if time.monotonic() > deadline:
                    raise TimeoutError("特征码解析超过本次时间限制")
                for signature, offset in anchors[keys[anchor_index]]:
                    location = begin - offset
                    if len(matches[signature]) < 2 and location >= 0 and patterns[signature].match(raw, location):
                        matches[signature].append(section.VirtualAddress + location)
        for signature, locations in matches.items():
            address = locations[0] if len(locations) == 1 else None
            if address is not None and signature.split()[0].upper() in ("E8", "E9"):
                address += 5 + int.from_bytes(image.read(address + 1, 4), "little", signed=True)
            resolutions[signature].append({"matches": locations, "address": address})
        print(f"已完成批量特征码解析：{image.path}，{len(signatures)} 个声明", flush=True)
    return resolutions


class Analyzer:
    def __init__(self, source, target, deadline):
        self.source = source
        self.target = target
        self.deadline = deadline
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.decoder.detail = True
        self.pairs = {}
        self.reasons = {}
        self.groups = []
        self.allocations = [{}, {}]
        self.register_families = {}
        for register in range(1, capstone.x86.X86_REG_ENDING):
            name = self.decoder.reg_name(register)
            if re.fullmatch(r"[re]?(ax|bx|cx|dx|si|di|bp|sp)|[abcd][lh]|[sd]il|[bs]pl", name):
                family = name.lstrip("re").removesuffix("l")
                family = {"al": "ax", "ah": "ax", "bl": "bx", "bh": "bx", "cl": "cx", "ch": "cx", "dl": "dx", "dh": "dx"}.get(name, family)
                self.register_families[register] = family
            elif re.fullmatch(r"r\d+[dwb]?", name):
                self.register_families[register] = name.rstrip("dwb")

    @lru_cache(maxsize=128)
    def instructions(self, image, address):
        function = image.functions.get(address)
        if function is None or function.end - function.start > 65536:
            return []
        return list(self.decoder.disasm(image.read(address, function.end - address), address))

    def shape(self, instructions):
        shape = []
        for instruction in instructions:
            operands = []
            for operand in instruction.operands:
                if operand.type == capstone.x86.X86_OP_REG:
                    operands.append((operand.type, operand.reg, operand.size))
                elif operand.type == capstone.x86.X86_OP_MEM:
                    operands.append((operand.type, operand.mem.base, operand.mem.index, operand.mem.scale, operand.size))
                else:
                    value = operand.imm
                    if instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_JUMP):
                        value = 0
                    operands.append((operand.type, value, operand.size))
            shape.append((instruction.id, tuple(operands)))
        return tuple(shape)

    def index(self, image_indices=(0, 1)):
        self.groups = [{}, {}]
        for image_index in image_indices:
            image = (self.source, self.target)[image_index]
            groups = defaultdict(list)
            for count, address in enumerate(image.starts):
                if count % 1000 == 0 and time.monotonic() > self.deadline:
                    raise TimeoutError("函数索引超过本次时间限制，请缩小输入或增加分段缓存")
                instructions = self.instructions(image, address)
                for index, instruction in enumerate(instructions):
                    operands = instruction.operands
                    if instruction.id != capstone.x86.X86_INS_MOV or len(operands) != 2:
                        continue
                    if operands[0].type != capstone.x86.X86_OP_REG or operands[0].reg != capstone.x86.X86_REG_ECX or operands[1].type != capstone.x86.X86_OP_IMM:
                        continue
                    size = operands[1].imm
                    tail = instructions[index + 1:index + 4]
                    if len(tail) != 3:
                        continue
                    allocation, transfer, construction = tail[:3]
                    if not allocation.group(capstone.CS_GRP_CALL) or not construction.group(capstone.CS_GRP_CALL):
                        continue
                    if transfer.id != capstone.x86.X86_INS_MOV or transfer.op_str != "rcx, rax":
                        continue
                    if allocation.operands[0].type != capstone.x86.X86_OP_IMM or construction.operands[0].type != capstone.x86.X86_OP_IMM:
                        continue
                    constructor = construction.operands[0].imm
                    self.allocations[image_index].setdefault(constructor, []).append({
                        "size": size, "allocator": allocation.operands[0].imm,
                        "instruction": image.base + instruction.address,
                    })
                if len(instructions) < 6:
                    continue
                digest = hashlib.blake2b(repr(self.shape(instructions)).encode(), digest_size=20).hexdigest()
                groups[digest].append(address)
            self.groups[image_index] = groups
            print(f"已建立函数索引：{image.path}，{sum(map(len, groups.values()))} 个函数", flush=True)
        self.match()

    def match(self):
        for digest, addresses in self.groups[0].items():
            targets = self.groups[1].get(digest, [])
            if len(addresses) == len(targets) == 1:
                self.pairs[addresses[0]] = targets[0]
                self.reasons[addresses[0]] = "unique-instruction-shape"

    def accesses(self, instructions):
        if not instructions:
            return {}
        positions = {instruction.address: index for index, instruction in enumerate(instructions)}
        predecessors = defaultdict(set)
        successors = defaultdict(set)
        for index, instruction in enumerate(instructions):
            if instruction.group(capstone.CS_GRP_JUMP):
                for operand in instruction.operands:
                    if operand.type == capstone.x86.X86_OP_IMM and operand.imm in positions:
                        successors[index].add(positions[operand.imm])
            if index + 1 < len(instructions) and instruction.id != capstone.x86.X86_INS_JMP and not instruction.group(capstone.CS_GRP_RET):
                successors[index].add(index + 1)
            for destination in successors[index]:
                predecessors[destination].add(index)
        incoming = {0: {capstone.x86.X86_REG_RCX: 0}}
        outgoing = {}
        pending = deque([0])
        iterations = 0
        while pending:
            iterations += 1
            if iterations % 1024 == 0 and time.monotonic() > self.deadline:
                raise TimeoutError("控制流分析超过本次时间限制")
            index = pending.popleft()
            states = [outgoing[parent] for parent in predecessors[index] if parent in outgoing]
            if index == 0:
                states.append({capstone.x86.X86_REG_RCX: 0})
            if not states:
                continue
            aliases = {register: offset for register, offset in states[0].items() if all(state.get(register) == offset for state in states[1:])}
            incoming[index] = aliases
            updated = self.transfer(instructions[index], aliases)
            if outgoing.get(index) != updated:
                outgoing[index] = updated
                pending.extend(successors[index])
        result = {}
        for index, instruction in enumerate(instructions):
            aliases = incoming.get(index, {})
            for slot, operand in enumerate(instruction.operands):
                if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base in aliases and not operand.mem.index:
                    result[(index, slot)] = (aliases[operand.mem.base] + operand.mem.disp, operand.size, instruction.address)
        return result

    def refine(self, needed):
        occupied = set(self.pairs.values())
        for _ in range(4):
            added = 0
            for digest, sources in self.groups[0].items():
                targets = self.groups[1].get(digest, [])
                if not targets or len(sources) > 32 or len(targets) > 32:
                    continue
                for source in sources:
                    if time.monotonic() > self.deadline:
                        raise TimeoutError("函数调用关系分析超过本次时间限制")
                    if source in self.pairs or source not in needed:
                        continue
                    left = self.instructions(self.source, source)
                    known = {
                        index: self.pairs[instruction.operands[0].imm]
                        for index, instruction in enumerate(left)
                        if instruction.group(capstone.CS_GRP_CALL)
                        and instruction.operands[0].type == capstone.x86.X86_OP_IMM
                        and instruction.operands[0].imm in self.pairs
                    }
                    if not known:
                        continue
                    candidates = []
                    for target in targets:
                        if target in occupied:
                            continue
                        right = self.instructions(self.target, target)
                        if all(right[index].operands[0].imm == address for index, address in known.items()):
                            candidates.append(target)
                    if len(candidates) == 1:
                        self.pairs[source] = candidates[0]
                        self.reasons[source] = "function-call-graph"
                        occupied.add(candidates[0])
                        added += 1
            if not added:
                break

    def transfer(self, instruction, incoming):
        aliases = incoming.copy()
        operands = instruction.operands
        assignment = None
        if len(operands) == 2 and operands[0].type == capstone.x86.X86_OP_REG and operands[0].size == 8:
            if instruction.id == capstone.x86.X86_INS_MOV and operands[1].type == capstone.x86.X86_OP_REG:
                assignment = aliases.get(operands[1].reg)
            elif instruction.id == capstone.x86.X86_INS_LEA and operands[1].type == capstone.x86.X86_OP_MEM:
                memory = operands[1].mem
                if memory.base in aliases and not memory.index:
                    assignment = aliases[memory.base] + memory.disp
        _, written = instruction.regs_access()
        for register in written:
            for alias in list(aliases):
                if alias == register or self.register_families.get(alias, alias) == self.register_families.get(register, register):
                    aliases.pop(alias)
        if assignment is not None:
            aliases[operands[0].reg] = assignment
        if instruction.group(capstone.CS_GRP_CALL):
            for register in (capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RCX, capstone.x86.X86_REG_RDX, capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9, capstone.x86.X86_REG_R10, capstone.x86.X86_REG_R11):
                aliases.pop(register, None)
        return aliases

    def compare(self, definition, resolutions):
        evidence = defaultdict(list)
        methods = []
        size_evidence = []
        minimum_size = 0
        source_minimum_size = 0
        size_access_evidence = []
        for method in definition["methods"]:
            if time.monotonic() > self.deadline:
                raise TimeoutError("结构分析超过本次时间限制")
            if not method["instance"]:
                continue
            if "source_address" in method:
                left_resolution = {"address": method["source_address"]}
                right_resolution = {"address": None}
            else:
                left_resolution, right_resolution = resolutions[method["signature"]]
            source = left_resolution["address"]
            if source not in self.source.functions:
                methods.append({"name": method["name"], "status": "source-unresolved"})
                continue
            target = self.pairs.get(source)
            if target is None:
                target = right_resolution["address"]
            if target not in self.target.functions:
                methods.append({"name": method["name"], "status": "target-unresolved"})
                continue
            if method["name"] in ("Ctor", "ctor"):
                for allocation in self.allocations[0].get(source, []):
                    for target_allocation in self.allocations[1].get(target, []):
                        if allocation["size"] == definition["size"] and self.pairs.get(allocation["allocator"]) == target_allocation["allocator"] and allocation.get("argument") == target_allocation.get("argument"):
                            size_evidence.append({"source": allocation, "target": target_allocation})
            left = self.instructions(self.source, source)
            right = self.instructions(self.target, target)
            if self.shape(left) != self.shape(right):
                methods.append({"name": method["name"], "status": "body-changed", "source": source, "target": target})
                continue
            if right_resolution["address"] is not None and right_resolution["address"] != target:
                methods.append({"name": method["name"], "status": "signature-disagreement"})
                continue
            left_accesses = self.accesses(left)
            right_accesses = self.accesses(right)
            for key, (offset, width, address) in left_accesses.items():
                if key not in right_accesses:
                    continue
                new_offset, new_width, new_address = right_accesses[key]
                if right[key[0]].id != capstone.x86.X86_INS_LEA and new_offset >= 0:
                    source_minimum_size = max(source_minimum_size, offset + width)
                    if new_offset + new_width > minimum_size:
                        size_access_evidence = [{
                            "method": method["name"], "source_offset": offset, "target_offset": new_offset,
                            "width": width, "source_instruction": self.source.base + address,
                            "target_instruction": self.target.base + new_address,
                        }]
                    minimum_size = max(minimum_size, new_offset + new_width)
                if width == new_width:
                    evidence[offset].append({
                        "offset": new_offset, "width": width, "method": method["name"],
                        "source_instruction": self.source.base + address,
                        "target_instruction": self.target.base + new_address,
                    })
            methods.append({"name": method["name"], "status": "aligned", "source": source, "target": target})
        fields = []
        for field in definition["fields"]:
            observations = evidence[field["offset"]]
            candidates = sorted({item["offset"] for item in observations})
            status = "unobserved"
            if len(candidates) > 1:
                status = "conflict"
            elif candidates:
                status = "unchanged" if candidates[0] == field["offset"] else "candidate"
            fields.append({**field, "status": status, "candidates": candidates, "evidence": observations})
        sizes = sorted({item["target"]["size"] for item in size_evidence})
        size_status = "unproven"
        if len(sizes) > 1:
            size_status = "conflict"
        elif sizes:
            size_status = "allocation-unchanged" if sizes[0] == definition["size"] else "allocation-candidate"
        if minimum_size > definition["size"]:
            size_status = "access-range-increased" if minimum_size > source_minimum_size else "baseline-range-exceeds-declaration"
        return {
            **definition, "fields": fields, "methods": methods, "size_status": size_status,
            "source_minimum_observed_size": source_minimum_size, "minimum_observed_size": minimum_size,
            "size_candidates": sizes, "size_evidence": size_evidence, "size_access_evidence": size_access_evidence,
        }

    def mapped_instruction(self, address):
        function = self.source.function(address)
        if function is None or function.start not in self.pairs:
            return None
        if function.start == address:
            return self.target.base + self.pairs[function.start]
        source = self.instructions(self.source, function.start)
        target = self.instructions(self.target, self.pairs[function.start])
        if self.shape(source) != self.shape(target):
            return None
        for index, instruction in enumerate(source):
            if instruction.address == address:
                return self.target.base + target[index].address
        return None

    def recover_references(self, needed):
        votes = defaultdict(set)
        callers = {}
        for section in self.source.sections:
            if not section.Characteristics & 0x20000000:
                continue
            raw = self.source.contents[section.VirtualAddress]
            for opcode in (b"\xe8", b"\xe9"):
                location = raw.find(opcode)
                while location >= 0:
                    address = section.VirtualAddress + location
                    destination = address + 5 + int.from_bytes(raw[location + 1:location + 5], "little", signed=True)
                    if destination in needed:
                        function = self.source.function(address)
                        if function is not None and function.start in self.pairs:
                            if function.start not in callers:
                                left = self.instructions(self.source, function.start)
                                right = self.instructions(self.target, self.pairs[function.start])
                                callers[function.start] = self.shape(left) == self.shape(right)
                            if not callers[function.start]:
                                location = raw.find(opcode, location + 1)
                                continue
                            left = self.instructions(self.source, function.start)
                            right = self.instructions(self.target, self.pairs[function.start])
                            for index, instruction in enumerate(left):
                                if instruction.address != address or instruction.operands[0].type != capstone.x86.X86_OP_IMM:
                                    continue
                                candidate = right[index].operands[0].imm
                                if candidate in self.target.functions:
                                    votes[destination].add(candidate)
                    location = raw.find(opcode, location + 1)
        occupied = {target: source for source, target in self.pairs.items()}
        for source, targets in votes.items():
            if len(targets) == 1:
                target = next(iter(targets))
                if target not in occupied or occupied[target] == source:
                    self.pairs[source] = target
                    self.reasons[source] = "aligned-caller-reference"

    def collect_allocations(self, image, constructors, side):
        hits = set()
        for section in image.sections:
            if not section.Characteristics & 0x20000000:
                continue
            raw = image.contents[section.VirtualAddress]
            location = raw.find(b"\xe8")
            while location >= 0:
                address = section.VirtualAddress + location
                destination = address + 5 + int.from_bytes(raw[location + 1:location + 5], "little", signed=True)
                if destination in constructors:
                    function = image.function(address)
                    if function is not None:
                        hits.add((function.start, address, destination))
                location = raw.find(b"\xe8", location + 1)
        for start, address, constructor in sorted(hits):
            if time.monotonic() > self.deadline:
                raise TimeoutError("分配现场分析超过本次时间限制")
            instructions = self.instructions(image, start)
            positions = [index for index, item in enumerate(instructions) if item.address == address and item.id == capstone.x86.X86_INS_CALL]
            if not positions:
                continue
            position = positions[0]
            preceding_calls = [index for index in range(max(0, position - 16), position) if instructions[index].group(capstone.CS_GRP_CALL)]
            if not preceding_calls:
                continue
            allocation_index = preceding_calls[-1]
            allocation = instructions[allocation_index]
            if allocation.operands[0].type != capstone.x86.X86_OP_IMM:
                continue
            aliases = {capstone.x86.X86_REG_RAX: 0}
            valid = True
            for instruction in instructions[allocation_index + 1:position]:
                if instruction.group(capstone.CS_GRP_JUMP):
                    operands = instruction.operands
                    if instruction.id == capstone.x86.X86_INS_JMP or not operands or operands[0].type != capstone.x86.X86_OP_IMM or operands[0].imm <= address:
                        valid = False
                        break
                aliases = self.transfer(instruction, aliases)
            if not valid or aliases.get(capstone.x86.X86_REG_RCX) != 0:
                continue
            arguments = {}
            for instruction in instructions[max(0, allocation_index - 12):allocation_index]:
                if instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_CALL):
                    arguments.clear()
                _, written = instruction.regs_access()
                for register in written:
                    arguments.pop(self.register_families.get(register), None)
                operands = instruction.operands
                if instruction.id == capstone.x86.X86_INS_MOV and len(operands) == 2 and operands[0].type == capstone.x86.X86_OP_REG and operands[1].type == capstone.x86.X86_OP_IMM:
                    family = self.register_families.get(operands[0].reg)
                    if family in ("cx", "dx", "r8") and 8 < operands[1].imm < image.size:
                        arguments[family] = operands[1].imm
            for argument, size in arguments.items():
                self.allocations[side].setdefault(constructor, []).append({
                    "size": size, "argument": argument, "allocator": allocation.operands[0].imm,
                    "instruction": image.base + allocation.address, "constructor_call": image.base + address,
                })


def main():
    parser = argparse.ArgumentParser(description="比较两个客户端的原生字段访问及源码特征码")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--root", action="append", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--source-index", type=Path)
    parser.add_argument("--target-index", type=Path)
    parser.add_argument("--phase", choices=("source", "target", "compare"), default="compare")
    parser.add_argument("--baseline-root", type=Path)
    parser.add_argument("--baseline-revision")
    parser.add_argument("--baseline", nargs=2, action="append", metavar=("ROOT", "REVISION"))
    parser.add_argument("--data", type=Path)
    parser.add_argument("--seconds", type=int, default=270, choices=range(1, 281), metavar="1..280")
    args = parser.parse_args()
    if args.config:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        parent = args.config.resolve().parent
        for name in ("source", "target", "report", "cache", "source_index", "target_index", "baseline_root", "data"):
            if getattr(args, name) is None and name in config:
                setattr(args, name, (parent / config[name]).resolve())
        if args.root is None:
            args.root = [(parent / root).resolve() for root in config["roots"]]
        if args.baseline_revision is None:
            args.baseline_revision = config.get("baseline_revision")
        args.baseline = (args.baseline or []) + [
            [str((parent / item["root"]).resolve()), item["revision"]]
            for item in config.get("baselines", [])
        ]
    if any(getattr(args, name) is None for name in ("source", "target", "root", "report", "cache")):
        parser.error("必须指定两个客户端、源码目录、报告和缓存路径，或提供包含这些值的 --config")
    started = time.monotonic()
    structures, signatures = declarations(args.root)
    current = {(item["path"], item["type"]): item for item in structures}
    current_signatures = defaultdict(list)
    for item in signatures:
        current_signatures[(item["path"], item["signature"])].append(item)
    if bool(args.baseline_root) != bool(args.baseline_revision):
        parser.error("基线目录与 Git 版本必须同时指定")
    baselines = [(Path(root), revision) for root, revision in args.baseline or []]
    if args.baseline_root:
        baselines.append((args.baseline_root, args.baseline_revision))
    for root, revision in baselines:
        baseline, baseline_signatures = declarations(
            [root], revision_contents(root, revision),
        )
        paths = {item["path"] for item in baseline}
        structures = [item for item in structures if item["path"] not in paths] + baseline
        signatures = [item for item in signatures if item["path"] not in paths] + baseline_signatures
    protected = {args.source.resolve(), args.target.resolve(), *(Path(item["path"]).resolve() for item in structures + signatures)}
    protected.update(path.resolve() for path in (args.data, args.config, args.source_index, args.target_index) if path is not None)
    outputs = {args.report.resolve(), args.cache.with_suffix(".source.json").resolve(), args.cache.with_suffix(".target.json").resolve()}
    if len(outputs) != 3 or protected.intersection(outputs):
        parser.error("报告与缓存必须互不相同，且不得覆盖输入")
    images = []
    for path in (args.source, args.target):
        image = Image(path)
        image.pe.close()
        image.pe = None
        images.append(image)
    analyzer = Analyzer(*images, started + args.seconds)
    identity = {"source_sha256": analyzer.source.sha256, "target_sha256": analyzer.target.sha256}
    if args.phase != "compare":
        side = 0 if args.phase == "source" else 1
        analyzer.index((side,))
        write_json(args.cache.with_suffix(f".{args.phase}.json"), {
            **identity, "index_schema": 1, "image_sha256": (analyzer.source, analyzer.target)[side].sha256,
            "groups": analyzer.groups[side], "allocations": analyzer.allocations[side],
        })
        return
    for side, key in enumerate(("source", "target")):
        cache_path = getattr(args, f"{key}_index") or args.cache.with_suffix(f".{key}.json")
        if not cache_path.exists():
            parser.error("请先分别使用 --phase source 和 --phase target 建立两端索引")
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if cached.get("index_schema") != 1 or cached.get("image_sha256") != (analyzer.source, analyzer.target)[side].sha256:
            parser.error("函数缓存与指定客户端不匹配")
        analyzer.groups.append(cached["groups"])
        analyzer.allocations[side] = {int(key): value for key, value in cached["allocations"].items()}
    analyzer.match()
    virtual_tables = {}
    if args.data:
        data = yaml.load(args.data.read_text(encoding="utf-8"), Loader=yaml.CSafeLoader)
        fingerprint = data.get("_crossclient", {}).get("target_sha256")
        if fingerprint is not None and fingerprint != analyzer.source.sha256:
            parser.error("命名数据与参考客户端不匹配")
        table_mapping = Mapping(analyzer.source, analyzer.target, addresses=analyzer.pairs.copy())
        table_mapping.match_vtables(data)
        for definition in structures:
            native = data.get("classes", {}).get(definition["type"]) or {}
            for address, name in (native.get("funcs") or {}).items():
                if name.lower() == "ctor":
                    definition["methods"].append({"name": name, "instance": True, "source_address": address - analyzer.source.base})
            tables = native.get("vtbls") or []
            if not tables:
                continue
            table = tables[0]["ea"] - analyzer.source.base
            if table in table_mapping.addresses:
                virtual_tables[(definition["path"], definition["type"])] = (table, table_mapping.addresses[table])
            for virtual in definition["virtuals"]:
                pointer = analyzer.source.read(table + virtual["slot"] * 8, 8)
                if len(pointer) == 8:
                    definition["methods"].append({
                        "name": virtual["name"], "instance": True,
                        "source_address": int.from_bytes(pointer, "little") - analyzer.source.base,
                    })
    baseline_keys = {(item["path"], item["signature"]) for item in signatures}
    additional = [item for key, values in current_signatures.items() if key not in baseline_keys for item in values]
    resolutions = resolve_many(
        (analyzer.source, analyzer.target), {item["signature"] for item in signatures + additional}, analyzer.deadline,
    )
    needed = {left["address"] for left, right in resolutions.values()} | {
        method["source_address"] for definition in structures for method in definition["methods"]
        if "source_address" in method
    }
    analyzer.refine(needed)
    analyzer.recover_references({
        left["address"] for left, right in resolutions.values()
        if left["address"] in analyzer.source.functions and left["address"] not in analyzer.pairs
    } | {
        method["source_address"] for definition in structures for method in definition["methods"]
        if "source_address" in method and method["source_address"] not in analyzer.pairs
    })
    constructors = set()
    for definition in structures:
        for method in definition["methods"]:
            if method["name"].lower() != "ctor":
                continue
            if "source_address" in method:
                constructors.add(method["source_address"])
            else:
                constructors.add(resolutions[method["signature"]][0]["address"])
    constructors.intersection_update(analyzer.source.functions)
    analyzer.collect_allocations(analyzer.source, constructors, 0)
    analyzer.collect_allocations(analyzer.target, {analyzer.pairs[address] for address in constructors if address in analyzer.pairs}, 1)
    results = [analyzer.compare(definition, resolutions) for definition in structures]
    for result in results:
        if time.monotonic() > analyzer.deadline:
            raise TimeoutError("虚表与当前声明核对超过本次时间限制")
        result["virtual_slots"] = []
        tables = virtual_tables.get((result["path"], result["type"]))
        if tables:
            source_table, target_table = tables
            pointers = []
            for slot in range(512):
                raw = analyzer.target.read(target_table + slot * 8, 8)
                if len(raw) != 8:
                    break
                pointer = int.from_bytes(raw, "little") - analyzer.target.base
                if not analyzer.target.executable(pointer):
                    break
                pointers.append(pointer)
            for virtual in result["virtuals"]:
                raw = analyzer.source.read(source_table + virtual["slot"] * 8, 8)
                pointer = int.from_bytes(raw, "little") - analyzer.source.base
                destination = analyzer.pairs.get(pointer)
                slots = [slot for slot, target in enumerate(pointers) if target == destination]
                status = "unresolved"
                if len(slots) == 1:
                    status = "unchanged" if slots[0] == virtual["slot"] else "candidate"
                result["virtual_slots"].append({**virtual, "status": status, "candidates": slots})
        present = current.get((result["path"], result["type"]))
        if present is None:
            continue
        result["current_sha256"] = present["sha256"]
        result["current_size"] = present["size"]
        result["current_size_span"] = present["size_span"]
        if present["size"] != result["size"] and result["size_status"] == "unproven":
            result["size_status"] = "already-updated"
        current_virtuals = {item["name"]: item for item in present["virtuals"]}
        for virtual in result["virtual_slots"]:
            if virtual["name"] in current_virtuals:
                virtual["current"] = current_virtuals[virtual["name"]]
                if virtual["status"] == "candidate" and virtual["candidates"] == [virtual["current"]["slot"]]:
                    virtual["status"] = "already-updated"
        current_fields = {item["name"]: item for item in present["fields"]}
        for field in result["fields"]:
            if field["name"] not in current_fields:
                field["status"] = "declaration-removed"
                continue
            field["current"] = current_fields[field["name"]]
            if field["status"] == "candidate" and field["candidates"] == [field["current"]["offset"]]:
                field["status"] = "already-updated"
    signature_results = []
    occurrences = Counter()
    for declaration in signatures:
        if time.monotonic() > analyzer.deadline:
            raise TimeoutError("特征码身份核对超过本次时间限制")
        left, right = resolutions[declaration["signature"]]
        status = "source-unresolved"
        if len(left["matches"]) == 1:
            status = "target-unresolved"
            if len(right["matches"]) == 1:
                mapped = analyzer.pairs.get(left["address"])
                status = "matched" if mapped == right["address"] else "unverified-target"
                if mapped is not None and mapped != right["address"]:
                    status = "wrong-target"
        mapped_match = analyzer.mapped_instruction(left["matches"][0]) if len(left["matches"]) == 1 else None
        key = (declaration["path"], declaration["signature"])
        position = occurrences[key]
        occurrences[key] += 1
        if position < len(current_signatures[key]):
            declaration = current_signatures[key][position]
        else:
            status = "declaration-updated"
        signature_results.append({**declaration, "status": status, "source": left, "target": right, "mapped_target": analyzer.pairs.get(left["address"]), "mapped_match": mapped_match})
    for declaration in additional:
        left, right = resolutions[declaration["signature"]]
        status = "current-target-unresolved" if len(right["matches"]) != 1 else "current-target-unique"
        expected = None
        tentative = None
        baseline_signature = None
        for definition in structures:
            if definition["path"] != declaration["path"]:
                continue
            present = current.get((definition["path"], definition["type"]))
            if present is None:
                continue
            names = {method["name"] for method in present["methods"] if method.get("signature") == declaration["signature"]}
            for method in definition["methods"]:
                if method["name"] not in names or "signature" not in method:
                    continue
                baseline_signature = method["signature"]
                old_left, old_right = resolutions[baseline_signature]
                expected = analyzer.pairs.get(old_left["address"])
                tentative = old_right["address"]
                if expected is None and old_left["address"] in analyzer.source.functions and tentative in analyzer.target.functions:
                    source_body = analyzer.instructions(analyzer.source, old_left["address"])
                    target_body = analyzer.instructions(analyzer.target, tentative)
                    if source_body and analyzer.shape(source_body) == analyzer.shape(target_body):
                        expected = tentative
                if expected is not None and old_right["address"] not in (None, expected):
                    tentative = None
        if expected is not None:
            status = "target-unresolved" if len(right["matches"]) != 1 else "matched"
            if len(right["matches"]) == 1 and right["address"] != expected:
                status = "wrong-target"
        elif tentative is not None and right["address"] is not None and tentative != right["address"]:
            status = "baseline-signature-disagreement"
        signature_results.append({
            **declaration, "status": status, "source": left, "target": right,
            "mapped_target": expected, "mapped_match": analyzer.target.base + expected if expected is not None else None,
            "baseline_signature": baseline_signature,
            "baseline_pattern_target": tentative,
        })
    summary = {
        "structures": len(results), "mapped_functions": len(analyzer.pairs),
        "fields": dict(Counter(field["status"] for item in results for field in item["fields"])),
        "signatures": dict(Counter(item["status"] for item in signature_results)),
        "sizes": dict(Counter(item["size_status"] for item in results)),
        "virtual_slots": dict(Counter(item["status"] for definition in results for item in definition["virtual_slots"])),
        "allocation_sites": {"source": sum(map(len, analyzer.allocations[0].values())), "target": sum(map(len, analyzer.allocations[1].values()))},
    }
    write_json(args.report, {
        "schema": 1, "complete": True, **identity, "source": str(args.source.resolve()), "target": str(args.target.resolve()),
        "baselines": [{"root": str(root.resolve()), "revision": revision} for root, revision in baselines],
        "summary": summary, "structures": results, "signatures": signature_results,
    })
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
