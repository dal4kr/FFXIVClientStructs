from __future__ import annotations

import ast
import copy
import hashlib
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import capstone

from ffxiv_crossclient import (
    Function,
    Mapping,
    describe_code,
    find_masked,
    recover_declared,
    relocate_data,
    resolve_symbols,
    validate_declared,
)
from ffxiv_crossclient_ida import (
    configure_native,
    import_expansion,
    load_script,
    normalize_primary_bases,
    rebase_data,
)
from ffxiv_crossclient_ida import run as import_generated


class MemoryImage:
    def __init__(self, code, base=0x140000000):
        self.base = base
        self.size = 0x2000
        self.sha256 = hashlib.sha256(code).hexdigest()
        self.sections = [
            SimpleNamespace(
                VirtualAddress=0x100,
                SizeOfRawData=len(code),
                Characteristics=0x20000000,
                Name=b".text",
            )
        ]
        self.contents = {0x100: code}
        self.functions = {}

    def read(self, rva, length):
        offset = rva - 0x100
        if offset < 0:
            return b""
        return self.contents[0x100][offset : offset + length]

    def section(self, rva):
        return next(
            (
                section
                for section in self.sections
                if section.VirtualAddress
                <= rva
                < section.VirtualAddress + section.SizeOfRawData
            ),
            None,
        )

    def executable(self, rva):
        return self.section(rva) is not None

    def function(self, rva):
        return next(
            (
                function
                for function in self.functions.values()
                if function.start <= rva < function.end
            ),
            None,
        )


class MatchingTests(unittest.TestCase):
    def test_masked_search_handles_regex_bytes_and_newline(self):
        image = MemoryImage(b"\x2e\x28\x5b\x0a\x29\xc3")
        self.assertEqual(
            find_masked(
                image, b"\x2e\x28\x5b\x00\x29\xc3", b"\xff\xff\xff\x00\xff\xff"
            ),
            [0x100],
        )

    def test_masked_search_rejects_ambiguity(self):
        image = MemoryImage(b"\x48\x8b\x05\x01\x02\x03\x04\xc3" * 2)
        matches = find_masked(
            image,
            b"\x48\x8b\x05\x00\x00\x00\x00\xc3",
            b"\xff\xff\xff\x00\x00\x00\x00\xff",
        )
        self.assertEqual(matches, [0x100, 0x108])

    def test_masked_search_rejects_section_boundary(self):
        image = MemoryImage(b"\x48\x8b\x05")
        self.assertEqual(
            find_masked(image, b"\x00\x48\x8b\x05", b"\x00\xff\xff\xff"), []
        )

    def test_normalization_preserves_constants(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        left = MemoryImage(b"\xb8\x01\x00\x00\x00\xc3")
        right = MemoryImage(b"\xb8\x02\x00\x00\x00\xc3")
        self.assertNotEqual(
            describe_code(left, decoder, 0x100, left.read(0x100, 6), 0x106)[0],
            describe_code(right, decoder, 0x100, right.read(0x100, 6), 0x106)[0],
        )

    def test_normalization_follows_signed_rip(self):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        image = MemoryImage(b"\x48\x8b\x05" + struct.pack("<i", -0x20) + b"\xc3")
        normalized, references, regions, consumed = describe_code(
            image, decoder, 0x100, image.read(0x100, 8), 0x108
        )
        self.assertEqual(normalized, b"\x48\x8b\x05\x00\x00\x00\x00\xc3")
        self.assertEqual(references, ((0, 0xE7),))
        self.assertEqual(regions, [(3, 4)])
        self.assertEqual(consumed, 8)

    def test_conflict_invalidates_interior_addresses(self):
        source = MemoryImage(bytes(64))
        target = MemoryImage(bytes(64))
        source.functions[0x100] = Function(0x100, 0x120)
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x100, "test")
        mapping.spans[0x100] = (0x100, 0x20)
        self.assertEqual(mapping.resolve(0x108), 0x108)
        mapping.add(0x100, 0x110, "conflict")
        self.assertIsNone(mapping.resolve(0x108))

    def test_cached_spans_preserve_interior_addresses(self):
        source = MemoryImage(bytes(64))
        target = MemoryImage(bytes(64))
        source.functions[0x100] = Function(0x100, 0x120)
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x108, "test")
        mapping.spans[0x100] = (0x108, 0x20)
        loaded = Mapping(source, target)
        loaded.load(mapping.payload())
        self.assertEqual(loaded.resolve(0x118), 0x120)
        invalid = mapping.payload()
        invalid["target_sha256"] = "invalid"
        with self.assertRaises(ValueError):
            loaded.load(invalid)

    def test_unresolved_addresses_never_survive_relocation(self):
        image = MemoryImage(bytes(64))
        mapping = Mapping(image, image)
        mapping.add(0x100, 0x110, "test")
        data = {
            "globals": {image.base + 0x100: "Known", image.base + 0x200: "Missing"},
            "classes": {
                "Example": {
                    "vtbls": [{"ea": 0, "base": "Parent"}],
                    "vfuncs": {3: "Update"},
                }
            },
        }
        original = copy.deepcopy(data)
        result, report = relocate_data(data, mapping)
        self.assertEqual(result["globals"], {image.base + 0x110: "Known"})
        self.assertEqual(result["classes"]["Example"]["vfuncs"], {3: "Update"})
        self.assertEqual(result["classes"]["Example"]["vtbls"][0]["ea"], 0)
        self.assertEqual(report["unresolved_count"], 1)
        self.assertEqual(data, original)

    def test_native_signatures_follow_calls(self):
        image = MemoryImage(b"\xe8\x03\x00\x00\x00\x90\x91\x92\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [
                    {"name": "Run", "signature": "E8 ?? ?? ?? ?? 90 91 92"}
                ],
            }
        ]
        result = resolve_symbols(structures, image)
        self.assertEqual(
            result["data"]["classes"]["Example"]["funcs"], {image.base + 0x108: "Run"}
        )
        self.assertEqual(result["unresolved"], [])

    def test_native_static_offsets_remain_signed(self):
        image = MemoryImage(
            b"\x90" * 16 + b"\x48\x8d\x05" + struct.pack("<i", -0x17) + b"\xc3"
        )
        structures = [
            {
                "type": "Example",
                "static_members": [
                    {
                        "name": "Instance",
                        "signature": "48 8D 05 ?? ?? ?? ?? C3",
                        "relative_follow_offsets": [3],
                        "is_pointer": False,
                    }
                ],
            }
        ]
        result = resolve_symbols(structures, image)
        self.assertEqual(
            result["data"]["classes"]["Example"]["instances"][0]["ea"],
            image.base + 0x100,
        )

    def test_native_function_rejects_interior_signature(self):
        image = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3")
        image.functions[0x100] = Function(0x100, 0x107)
        result = resolve_symbols(
            [
                {
                    "type": "Example",
                    "member_functions": [
                        {"name": "Run", "signature": "B8 01 02 03 04 C3"}
                    ],
                }
            ],
            image,
        )
        self.assertFalse(next(iter(result["resolved_signatures"].values()))["function"])
        self.assertNotIn("Example", result["data"]["classes"])
        self.assertEqual(len(result["unresolved"]), 1)

    def test_declared_recovery_requires_reference_address(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        data = {"classes": {"Example": {"funcs": {source.base + 0x107: "Run"}}}}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.addresses, {})
        data["classes"]["Example"]["funcs"] = {source.base + 0x100: "Run"}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.resolve(0x100), 0x101)

    def test_declared_recovery_preserves_confirmed_mapping(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x107, "confirmed")
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        data = {"classes": {"Example": {"funcs": {source.base + 0x100: "Run"}}}}
        recover_declared(mapping, data, structures)
        self.assertEqual(mapping.resolve(0x100), 0x107)
        self.assertEqual(mapping.conflicts, set())

    def test_independent_signature_disagreement_is_quarantined(self):
        source = MemoryImage(b"\xb8\x01\x02\x03\x04\xc3\x90\xc3")
        target = MemoryImage(b"\x90\xb8\x01\x02\x03\x04\xc3\xc3")
        structures = [
            {
                "type": "Example",
                "member_functions": [{"name": "Run", "signature": "B8 01 02 03 04 C3"}],
            }
        ]
        mapping = Mapping(source, target)
        mapping.add(0x100, 0x107, "confirmed")
        mapping.symbols = resolve_symbols(structures, target)
        mapping.reference_symbols = resolve_symbols(structures, source)
        validate_declared(mapping, structures)
        self.assertIsNone(mapping.resolve(0x100))
        self.assertEqual(mapping.conflicts, {0x100})
        self.assertEqual(mapping.symbols["data"]["classes"]["Example"]["funcs"], {})
        self.assertFalse(
            next(iter(mapping.symbols["resolved_signatures"].values()))["function"]
        )
        self.assertEqual(len(mapping.symbols["mapping_disagreements"]), 1)
        before = copy.deepcopy(mapping.payload())
        validate_declared(mapping, structures)
        self.assertEqual(mapping.payload(), before)


class ImportTests(unittest.TestCase):
    @staticmethod
    def upstream_api():
        path = Path(__file__).with_name("ffxiv_structimporter.py").resolve()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        ida = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == "IdaApi"
        )
        methods = {
            "preprocess_yaml",
            "create_srclang_decl",
            "append_srclang_padding",
            "get_srclang_fill_type",
            "create_vtable",
        }
        ida.name = "ValidationApi"
        ida.bases = []
        ida.body = [
            node
            for node in ida.body
            if isinstance(node, ast.FunctionDef) and node.name in methods
        ]
        source = "import copy\nfrom structs_schema import *\n" + ast.unparse(ida)
        with patch.object(Path, "read_text", return_value=source):
            return load_script(path, {})

    @staticmethod
    def native_vtables(definition, fields):
        class Members(list):
            total_size = 0
            unpadded_size = 0
            vftable = False
            push_back = list.append

            def set_vftable(self):
                self.vftable = True

        class TypeInfo:
            def __init__(self, text=""):
                self.text = text
                self.function = None
                self.pointer = None

            def is_array(self):
                return "[" in self.text

            def get_named_type(self, library, name):
                self.text = name
                return name in database

            def get_udt_details(self, members):
                source = database[self.text]
                members.extend(copy.deepcopy(source))
                members.total_size = source.total_size
                members.unpadded_size = source.unpadded_size
                members.vftable = source.vftable
                return True

            def create_func(self, function):
                self.function = function
                return True

            def create_ptr(self, target):
                self.pointer = target
                return True

            def create_udt(self, members, kind):
                if len({member.name for member in members}) != len(members):
                    return False
                if any(
                    member.offset != index * 64 or member.size != 64
                    for index, member in enumerate(members)
                ):
                    return False
                self.members = copy.deepcopy(members)
                return members.total_size == len(members) * 8

            def set_named_type(self, library, name, flags):
                database[name] = self.members
                return 0

        class Member(SimpleNamespace):
            def __init__(self, source=None, **attributes):
                if source is not None:
                    attributes = copy.deepcopy(vars(source))
                super().__init__(**attributes)

            def is_gap(self):
                return self.name.startswith("gap")

        class FunctionData(list):
            push_back = list.append

        members = Members()
        for offset, size, name, text in fields:
            members.append(
                Member(
                    offset=offset * 8,
                    size=size * 8,
                    name=name,
                    type=TypeInfo(text),
                    cmt=name + " 说明",
                )
            )
        members.total_size = max(
            (offset + size for offset, size, _, _ in fields), default=0
        )
        database = {definition.type + "_vtbl": members}
        types = SimpleNamespace(
            tinfo_t=TypeInfo,
            udt_type_data_t=Members,
            udm_t=Member,
            func_type_data_t=FunctionData,
            funcarg_t=SimpleNamespace,
            CM_CC_FASTCALL=1,
            BTF_STRUCT=1,
            NTF_REPLACE=1,
            TERR_OK=0,
            tinfo_errstr=str,
        )
        api = SimpleNamespace(
            clean_name=lambda name: name,
            clean_struct_name=lambda name: name,
            get_struct_id=lambda name: name,
            get_struct=lambda name: SimpleNamespace(name=name),
            create_struct_member=lambda *args: False,
            get_idc_type_from_ida_type=lambda name: 1,
            get_size_from_ida_type=lambda name: 8,
            get_struct_member_by_name=lambda table, name: next(
                (member for member in database[table.name] if member.name == name),
                None,
            ),
            get_tinfo_from_type=TypeInfo,
            get_fallback_vfunc_name=lambda name, slot: None,
            get_yaml=lambda: SimpleNamespace(structs=[]),
            preprocess_yaml=lambda definitions: None,
        )
        modules = {
            "ida_bytes": SimpleNamespace(),
            "ida_funcs": SimpleNamespace(),
            "ida_idaapi": SimpleNamespace(BADADDR=-1),
            "ida_typeinf": types,
        }
        with patch.dict("sys.modules", modules):
            configure_native(api, {"resolved_signatures": {}, "image_base": 0}, 0)
        return api, database

    def test_vtable_replaces_existing_slot_and_preserves_unknown_prototype(self):
        definition = SimpleNamespace(
            type="AdventureEventHandler",
            vtable_size=24,
            virtual_functions=[
                SimpleNamespace(
                    name="Setup", offset=16, return_type="byte", parameters=[]
                )
            ],
        )
        api, database = self.native_vtables(
            definition,
            [
                (0, 8, "dtor", "void (*)()"),
                (8, 8, "vf1", "__int64"),
                (16, 8, "vf2", "__int64"),
            ],
        )
        original = self.upstream_api()["ValidationApi"].create_vtable
        with self.assertRaisesRegex(RuntimeError, "Failed to find member Setup"):
            original(api, definition)
        for _ in range(2):
            api.create_vtable(definition)
            members = database["AdventureEventHandler_vtbl"]
            self.assertEqual(
                [member.name for member in members], ["dtor", "vf1", "Setup"]
            )
            self.assertEqual(members[0].type.text, "void (*)()")
            self.assertEqual(members[0].cmt, "dtor 说明")
            self.assertEqual(members[2].type.pointer.function.rettype.text, "byte")
            self.assertEqual(len(members[2].type.pointer.function), 0)
            self.assertEqual(members.total_size, 24)
            self.assertTrue(members.vftable)

    def test_vtable_splits_gaps_and_disambiguates_names_by_slot(self):
        functions = [
            SimpleNamespace(
                name=name, offset=index * 8, return_type=result, parameters=[]
            )
            for index, (name, result) in enumerate(
                [
                    ("ProcessUIEvent", "void"),
                    ("ProcessUIEvent", "byte"),
                    ("ProcessUIEvent_vf1", None),
                ]
            )
        ]
        definition = SimpleNamespace(
            type="Example", vtable_size=32, virtual_functions=functions
        )
        api, database = self.native_vtables(definition, [(0, 32, "gap0", "_BYTE[32]")])
        api.create_vtable(definition)
        members = database["Example_vtbl"]
        self.assertEqual(
            [member.name for member in members],
            ["ProcessUIEvent", "ProcessUIEvent_vf1_", "ProcessUIEvent_vf1", "vf3"],
        )
        self.assertEqual([member.offset for member in members], [0, 64, 128, 192])
        self.assertEqual(members[0].type.pointer.function.rettype.text, "void")
        self.assertEqual(members[1].type.pointer.function.rettype.text, "byte")
        self.assertEqual(members[2].type.text, "__int64")

    def test_polymorphic_prefix_is_imported_as_primary_base(self):
        module = self.upstream_api()
        field = module["DefinedStructField"]
        structure = module["DefinedStruct"]
        function = module["DefinedStructVFunc"]
        definitions = module["DefinedStructExport"](
            [],
            [
                structure(
                    "AgentInterface",
                    "AgentInterface",
                    "",
                    [],
                    40,
                    None,
                    [function("Show", "void", 0, [])],
                    [],
                    False,
                    None,
                    None,
                ),
                structure(
                    "AgentCollectablesShop",
                    "AgentCollectablesShop",
                    "",
                    [
                        field("AgentInterface", "AgentInterface", 0, False),
                        field("Data", "unsigned __int64", 40, False),
                    ],
                    48,
                    None,
                    [function("Show", "void", 0, [])],
                    [],
                    False,
                    None,
                    None,
                ),
            ],
        )
        api = module["ValidationApi"]()
        api.srclang_importer = True
        api.full_padding = False
        api.data_yaml = {}
        api.clean_struct_name = lambda name: name
        api.clean_name = lambda name: name
        api.get_srclang_type_name = lambda name: name
        api.get_struct_flag = lambda: 1
        api.get_enum_flag = lambda: 2
        api.get_idc_type_from_ida_type = lambda name: (
            1 if name == "AgentInterface" else 3
        )
        api.get_tinfo_from_type = lambda name: SimpleNamespace(get_size=lambda: 40)
        api.get_size_from_ida_type = lambda name: 8
        original = copy.deepcopy(definitions)
        api.preprocess_yaml(original)
        before = api.create_srclang_decl(original.structs[1])
        self.assertIn("AgentInterface AgentInterface;", before)
        self.assertTrue(original.structs[1].srclang_needs_vfptr)
        api.get_yaml = lambda: definitions
        with patch.dict(
            "sys.modules",
            {
                "ida_bytes": SimpleNamespace(),
                "ida_funcs": SimpleNamespace(),
                "ida_idaapi": SimpleNamespace(BADADDR=-1),
                "ida_typeinf": SimpleNamespace(),
            },
        ):
            configure_native(api, {"resolved_signatures": {}, "image_base": 0}, 0)
            api.preprocess_yaml(definitions)
        after = api.create_srclang_decl(definitions.structs[1])
        self.assertIn(": AgentInterface", after)
        self.assertNotIn("AgentInterface AgentInterface;", after)
        self.assertFalse(definitions.structs[1].srclang_needs_vfptr)
        self.assertTrue(definitions.structs[1].fields[0].srclang_is_baseclass)
        self.assertEqual(definitions.structs[1].fields[0].offset, 0)

    def test_existing_virtual_base_preserves_timeline_padding(self):
        module = self.upstream_api()
        field = module["DefinedStructField"]
        structure = module["DefinedStruct"]
        function = module["DefinedStructVFunc"]
        definitions = module["DefinedStructExport"](
            [],
            [
                structure(
                    "AtkEventTarget",
                    "AtkEventTarget",
                    "",
                    [],
                    8,
                    None,
                    None,
                    [],
                    False,
                    None,
                    None,
                ),
                structure(
                    "AtkResNode",
                    "AtkResNode",
                    "",
                    [
                        field("AtkEventTarget", "AtkEventTarget", 0, True),
                        field("NodeId", "unsigned int", 8, False),
                        field("Timeline", "void*", 16, False),
                    ],
                    24,
                    None,
                    [function("Destroy", "void", 8, [])],
                    [],
                    False,
                    None,
                    None,
                ),
            ],
        )
        api = module["ValidationApi"]()
        api.srclang_importer = True
        api.full_padding = False
        api.data_yaml = {}
        api.get_yaml = lambda: definitions
        api.clean_struct_name = lambda name: name
        api.clean_name = lambda name: name
        api.get_srclang_type_name = lambda name: name
        api.get_struct_flag = lambda: 1
        api.get_enum_flag = lambda: 2
        api.get_idc_type_from_ida_type = lambda name: (
            1 if name == "AtkEventTarget" else 3
        )
        api.get_tinfo_from_type = lambda name: SimpleNamespace(get_size=lambda: 8)
        api.get_size_from_ida_type = lambda name: 4 if name == "unsigned int" else 8

        def details(members):
            members.append(SimpleNamespace(offset=0, is_vftable=lambda: True))
            return True

        with patch.dict(
            "sys.modules",
            {
                "ida_bytes": SimpleNamespace(),
                "ida_funcs": SimpleNamespace(),
                "ida_idaapi": SimpleNamespace(BADADDR=-1),
                "ida_typeinf": SimpleNamespace(
                    tinfo_t=lambda: SimpleNamespace(
                        get_named_type=lambda library, name: name == "AtkEventTarget",
                        get_udt_details=details,
                    ),
                    udt_type_data_t=list,
                ),
            },
        ):
            configure_native(api, {"resolved_signatures": {}, "image_base": 0}, 0)
            api.preprocess_yaml(definitions)
        self.assertIsNotNone(definitions.structs[0].virtual_functions)
        self.assertFalse(definitions.structs[1].srclang_needs_vfptr)
        declaration = api.create_srclang_decl(definitions.structs[1])
        self.assertIn("char field_C[4];", declaration)
        self.assertLess(declaration.index("NodeId;"), declaration.index("field_C[4]"))
        self.assertLess(declaration.index("field_C[4]"), declaration.index("Timeline;"))

    def test_srclang_cursor_uses_field_end_instead_of_implicit_vfptr(self):
        path = Path(__file__).with_name("ffxiv_structimporter.py").resolve()
        source = "class Api:\n    def create_srclang_decl(self):\n        cur_size = 8\n        offset = 0\n        field_size = 8\n        cur_size += field_size\n        offset = 8\n        field_size = 4\n        cur_size += field_size\n        return cur_size\n"
        with patch.object(Path, "read_text", return_value=source):
            module = load_script(path, {})
        self.assertEqual(module["Api"]().create_srclang_decl(), 12)

    def test_expansion_notes_accept_upstream_and_attribute_bitfields(self):
        directory = Path(__file__).resolve().parent
        payload = {
            "expansion_types": ["Child"],
            "generated_types": [],
            "expansion_enums": [],
            "enums": [],
            "structs": [
                {
                    "type": "Child",
                    "union": False,
                    "fields": [
                        {
                            "name": "Upstream",
                            "bits": [
                                {
                                    "name": "Enabled",
                                    "offset": 1,
                                    "size": 1,
                                    "type": "bool",
                                }
                            ],
                        },
                        {
                            "name": "Expansion",
                            "bits": [{"arguments": ["Visible", 2, 1], "type": "bool"}],
                        },
                    ],
                }
            ],
        }
        members = [
            SimpleNamespace(name=name, cmt="") for name in ("Upstream", "Expansion")
        ]
        methods = (
            "delete_struct",
            "create_struct_members",
            "create_vtable",
            "create_union",
            "update_member_func",
            "update_static_member",
            "update_virt_func",
            "delete_enum",
            "create_enum_struct",
            "create_struct",
            "finalise_struct",
        )
        api = SimpleNamespace(
            srclang_importer=False,
            clean_struct_name=lambda name: name,
            **{name: lambda *arguments: None for name in methods},
        )
        type_api = SimpleNamespace(
            tinfo_t=lambda: SimpleNamespace(
                get_named_type=lambda library, name: True,
                get_udt_details=lambda output: output.extend(members) is None,
                create_udt=lambda output, kind: True,
                set_named_type=lambda library, name, flags: 0,
            ),
            udt_type_data_t=list,
            BTF_STRUCT=0,
            BTF_UNION=1,
            NTF_REPLACE=1,
            TERR_OK=0,
        )
        with (
            patch.dict("sys.modules", {"ida_typeinf": type_api}),
            patch("ffxiv_crossclient_ida.configure_native"),
            patch(
                "ffxiv_crossclient_ida.load_script",
                return_value={"api": api, "run": lambda: None},
            ),
        ):
            import_expansion(payload, {}, directory, 0)
        self.assertIn("Enabled：第 1 位起，共 1 位", members[0].cmt)
        self.assertIn("Visible：第 2 位起，共 1 位", members[1].cmt)

    def test_primary_base_normalization_preserves_aggregation_and_unions(self):
        for polymorphic, union, array in (
            (False, False, False),
            (True, True, False),
            (True, False, True),
        ):
            with self.subTest(polymorphic=polymorphic, union=union, array=array):
                member = SimpleNamespace(
                    name="Parent", type="Parent", offset=0, base=False
                )
                if array:
                    member.size = 2
                definitions = SimpleNamespace(
                    structs=[
                        SimpleNamespace(
                            type="Parent", virtual_functions=[], fields=[], union=False
                        ),
                        SimpleNamespace(
                            type="Child",
                            virtual_functions=[] if polymorphic else None,
                            fields=[member],
                            union=union,
                        ),
                    ]
                )
                normalize_primary_bases(definitions, {})
                self.assertFalse(member.base)

    def test_primary_base_normalization_follows_declared_inheritance(self):
        root = SimpleNamespace(
            type="Root", virtual_functions=[], fields=[], union=False
        )
        parent = SimpleNamespace(
            type="Parent",
            virtual_functions=None,
            union=False,
            fields=[
                SimpleNamespace(name="Root", type="Root", offset=0, base=True),
            ],
        )
        member = SimpleNamespace(name="Parent", type="Parent", offset=0, base=False)
        child = SimpleNamespace(
            type="Child", virtual_functions=[], fields=[member], union=False
        )
        definitions = SimpleNamespace(structs=[child, parent, root])
        normalize_primary_bases(definitions, {})
        self.assertTrue(member.base)
        normalize_primary_bases(definitions, {})
        self.assertTrue(member.base)

    def test_expansion_preserves_dependency_graph_and_existing_layout(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                calls = []
                directory = Path(__file__).resolve().parent
                payload = {
                    "expansion_types": ["Child"],
                    "generated_types": [],
                    "expansion_enums": [],
                    "structs": [
                        {"type": name, "fields": []} for name in ("Parent", "Child")
                    ],
                    "enums": [],
                }
                api = SimpleNamespace(
                    srclang_importer=True,
                    srclang_types={},
                    clean_struct_name=lambda name: name,
                    generate_hashed_type_name=lambda name: "struc_" + name,
                )
                methods = (
                    "delete_struct",
                    "create_struct",
                    "create_struct_members",
                    "finalise_struct",
                    "create_vtable",
                    "create_union",
                    "update_member_func",
                    "update_static_member",
                    "update_virt_func",
                    "delete_enum",
                    "create_enum_struct",
                )
                for name in methods:
                    setattr(
                        api,
                        name,
                        lambda *arguments, name=name, calls=calls: calls.append(
                            (name, arguments[-1].type)
                        ),
                    )

                def load(path, documents, directory=directory, fail=fail, api=api):
                    definitions = documents[directory / "ffxiv_structs.yml"]["structs"]

                    def run():
                        self.assertEqual(api.srclang_types["Child"], "struc_Child")
                        self.assertEqual(
                            [item["type"] for item in definitions], ["Parent", "Child"]
                        )
                        for name in (
                            "delete_struct",
                            "create_struct",
                            "create_struct_members",
                            "finalise_struct",
                        ):
                            for item in definitions:
                                if fail and name == "create_struct_members":
                                    raise RuntimeError("中止导入")
                                getattr(api, name)(SimpleNamespace(type=item["type"]))

                    return {"api": api, "run": run}

                type_api = SimpleNamespace(
                    tinfo_t=lambda: SimpleNamespace(
                        get_named_type=lambda library, name: True,
                        get_udt_details=lambda members: False,
                    ),
                    udt_type_data_t=list,
                )
                with (
                    patch.dict("sys.modules", {"ida_typeinf": type_api}),
                    patch("ffxiv_crossclient_ida.load_script", side_effect=load),
                    patch("ffxiv_crossclient_ida.configure_native"),
                ):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "中止导入"):
                            import_expansion(payload, {}, directory, 0x140000000)
                    else:
                        import_expansion(payload, {}, directory, 0x140000000)
                self.assertNotIn(("delete_struct", "Parent"), calls)
                self.assertNotIn(("create_struct_members", "Parent"), calls)
                self.assertIn(("create_struct", "Parent"), calls)
                self.assertEqual(calls.count(("finalise_struct", "Parent")), 1)
                self.assertEqual(calls.count(("finalise_struct", "Child")), 1)

    def test_entry_applies_database_base_only_once(self):
        data = {
            "_crossclient": {"image_base": 0x1000, "target_sha256": "test"},
            "classes": {"Example": {"funcs": {0x1100: "Run"}}},
        }
        imported = []
        class_type = SimpleNamespace(STANDARD_IMAGE_BASE=0x140000000)
        rename = {"FfxivClass": class_type, "load_data": lambda: None}
        importer = {"api": SimpleNamespace(can_run=lambda: True), "run": lambda: None}

        def load(path, documents):
            imported.append(next(iter(documents.values())))
            return rename if path.name == "ffxiv_idarename.py" else importer

        with (
            patch.dict(
                "sys.modules",
                {
                    "ida_auto": SimpleNamespace(auto_wait=lambda: None),
                    "ida_idaapi": SimpleNamespace(BADADDR=-1),
                    "ida_kernwin": SimpleNamespace(),
                    "ida_nalt": SimpleNamespace(get_imagebase=lambda: 0x2000),
                    "ida_name": SimpleNamespace(),
                },
            ),
            patch.object(Path, "read_text", return_value=json.dumps(data)),
            patch("ffxiv_crossclient_ida.verify_target"),
            patch("ffxiv_crossclient_ida.configure_native"),
            patch("ffxiv_crossclient_ida.load_script", side_effect=load),
            patch("builtins.print"),
        ):
            import_generated(data_path="generated.yml")
        self.assertEqual(class_type.STANDARD_IMAGE_BASE, 0x2000)
        self.assertEqual(len(imported), 2)
        for document in imported:
            self.assertEqual(document["classes"]["Example"]["funcs"], {0x2100: "Run"})

    def test_native_types_use_validated_address(self):
        class FunctionData(list):
            push_back = list.append

        applied = []
        type_api = SimpleNamespace(
            func_type_data_t=FunctionData,
            funcarg_t=SimpleNamespace,
            tinfo_t=lambda: SimpleNamespace(create_func=lambda function: True),
            CM_CC_FASTCALL=1,
            TINFO_DEFINITE=1,
            apply_tinfo=lambda address, info, flags: applied.append(address) is None,
        )
        field = SimpleNamespace(type="__int64", return_type="void", parameters=[])
        api = SimpleNamespace(
            get_tinfo_from_type=lambda value: value,
            get_vft_from_data=lambda name: {"ea": 0x2300},
            get_yaml=lambda: SimpleNamespace(structs=[SimpleNamespace(fields=[field])]),
            preprocess_yaml=lambda definitions: None,
        )
        manifest = {
            "image_base": 0x1000,
            "resolved_signatures": {
                "valid": {"address": 0x1100, "function": True},
                "interior": {"address": 0x1200, "function": False},
            },
            "resolved_statics": {},
        }
        with patch.dict(
            "sys.modules",
            {
                "ida_idaapi": SimpleNamespace(BADADDR=-1),
                "ida_typeinf": type_api,
                "ida_funcs": SimpleNamespace(
                    get_func=lambda address: SimpleNamespace(start_ea=address),
                    get_func_name=lambda address: "Run",
                ),
                "ida_bytes": SimpleNamespace(get_qword=lambda address: address + 0x100),
            },
        ):
            configure_native(api, manifest, 0x2000)
            self.assertEqual(api.get_yaml().structs[0].fields[0].type, "__fastcall")
            for signature in ("valid", "interior", "missing"):
                api.update_member_func(
                    SimpleNamespace(
                        signature=signature,
                        name="Run",
                        return_type="void",
                        parameters=[],
                    ),
                    SimpleNamespace(type="Example"),
                )
            api.update_virt_func(
                SimpleNamespace(
                    name="Run", offset=16, return_type="void", parameters=[]
                ),
                SimpleNamespace(type="Example"),
            )
        self.assertEqual(applied, [0x2100, 0x2410])

    def test_virtual_types_validate_entries_before_reading_optional_names(self):
        class FunctionData(list):
            push_back = list.append

        cases = [
            ("missing_table", None, 0x3000, 0x3000, "Run", False),
            ("missing_table_address", {}, 0x3000, 0x3000, "Run", False),
            ("zero_table_address", {"ea": 0}, 0x3000, 0x3000, "Run", False),
            ("null_target", {"ea": 0x2000}, 0, None, None, False),
            ("invalid_target", {"ea": 0x2000}, -1, None, None, False),
            ("unknown_function", {"ea": 0x2000}, 0x3000, None, None, False),
            ("interior_target", {"ea": 0x2000}, 0x3001, 0x3000, "Run", False),
            ("unnamed_function", {"ea": 0x2000}, 0x3000, 0x3000, None, True),
            ("empty_function_name", {"ea": 0x2000}, 0x3000, 0x3000, "", True),
            ("named_function", {"ea": 0x2000}, 0x3000, 0x3000, "Run", True),
            ("purecall", {"ea": 0x2000}, 0x3000, 0x3000, "_purecall", False),
            ("purecall_jump", {"ea": 0x2000}, 0x3000, 0x3000, "j__purecall", False),
            (
                "purecall_thunk",
                {"ea": 0x2000},
                0x3000,
                0x3000,
                "thunk__purecall",
                False,
            ),
        ]
        for label, table, target, head, name, expected in cases:
            with self.subTest(label=label):
                apply_type = Mock(return_value=True)
                get_name = Mock(return_value=name)
                get_function = Mock(
                    return_value=None
                    if head is None
                    else SimpleNamespace(start_ea=head)
                )
                read_slot = Mock(return_value=target)
                api = SimpleNamespace(
                    get_tinfo_from_type=lambda value: value,
                    get_vft_from_data=lambda value, table=table: table,
                    get_yaml=lambda: SimpleNamespace(structs=[]),
                    preprocess_yaml=lambda definitions: None,
                )
                with (
                    patch.dict(
                        "sys.modules",
                        {
                            "ida_idaapi": SimpleNamespace(BADADDR=-1),
                            "ida_typeinf": SimpleNamespace(
                                func_type_data_t=FunctionData,
                                funcarg_t=SimpleNamespace,
                                tinfo_t=lambda: SimpleNamespace(
                                    create_func=lambda function: True
                                ),
                                CM_CC_FASTCALL=1,
                                TINFO_DEFINITE=1,
                                apply_tinfo=apply_type,
                            ),
                            "ida_funcs": SimpleNamespace(
                                get_func=get_function, get_func_name=get_name
                            ),
                            "ida_bytes": SimpleNamespace(get_qword=read_slot),
                        },
                    ),
                    patch("builtins.print") as report,
                ):
                    configure_native(
                        api, {"resolved_signatures": {}, "image_base": 0}, 0
                    )
                    api.update_virt_func(
                        SimpleNamespace(
                            name="Run", offset=16, return_type="void", parameters=[]
                        ),
                        SimpleNamespace(type="Example"),
                    )
                if expected:
                    apply_type.assert_called_once()
                    self.assertEqual(apply_type.call_args.args[0], target)
                else:
                    apply_type.assert_not_called()
                if not table or not table.get("ea"):
                    read_slot.assert_not_called()
                    get_function.assert_not_called()
                    get_name.assert_not_called()
                elif target in (0, -1):
                    get_function.assert_not_called()
                    get_name.assert_not_called()
                elif head is None or head != target:
                    get_name.assert_not_called()
                    report.assert_called_once()
                    self.assertIn("Example.Run", report.call_args.args[0])
                else:
                    get_name.assert_called_once_with(target)

    def test_rebase_accepts_json_keys_and_preserves_zero(self):
        data = {
            "_crossclient": {
                "image_base": 0x1000,
                "resolved_signatures": {"test": {"match": 0x1010, "address": 0x1020}},
                "resolved_statics": {"test": 0x1030},
            },
            "globals": {"4112": "Global"},
            "functions": {},
            "classes": {
                "Example": {
                    "funcs": {"4128": "Run"},
                    "vtbls": [{"ea": 0}, {"ea": 0x1040}],
                }
            },
        }
        original = copy.deepcopy(data)
        result = rebase_data(data, 0x2000)
        self.assertEqual(result["globals"], {0x2010: "Global"})
        self.assertEqual(result["classes"]["Example"]["funcs"], {0x2020: "Run"})
        self.assertEqual(
            result["classes"]["Example"]["vtbls"], [{"ea": 0}, {"ea": 0x2040}]
        )
        self.assertEqual(
            result["_crossclient"]["resolved_signatures"]["test"]["address"], 0x2020
        )
        self.assertEqual(result["_crossclient"]["resolved_statics"]["test"], 0x2030)
        self.assertEqual(data, original)

    def test_existing_script_receives_generated_data_without_file_edits(self):
        path = Path(__file__).with_name("ffxiv_idarename.py").resolve()
        data = path.with_name("data.yml")
        source = "calls = []\ndef load_data():\n    calls.append(open(__file__.replace('ffxiv_idarename.py', 'data.yml')).read())\nload_data()\n"
        with patch.object(Path, "read_text", return_value=source):
            module = load_script(path, {data: {"generated": True}})
        self.assertEqual(module["calls"], [])
        module["load_data"]()
        self.assertIn("generated: true", module["calls"][0])
        self.assertEqual(len(module["calls"]), 1)

    def test_function_pointer_declaration_preserves_spacing_and_names(self):
        path = Path(__file__).with_name("ffxiv_structimporter.py").resolve()
        source = "class Api:\n    def get_srclang_type_name(self, value):\n        return value\n    def create_srclang_decl(self):\n        field_decl = 'void (*Callback)('\n        for name in ['first', 'second']:\n            field_decl = field_decl + self.get_srclang_type_name('int') + ''\n            field_decl = field_decl + name + ','\n        return field_decl[:-2] + ')'\n"
        with patch.object(Path, "read_text", return_value=source):
            module = load_script(path, {})
        self.assertEqual(
            module["Api"]().create_srclang_decl(),
            "void (*Callback)(int first,int second);",
        )


if __name__ == "__main__":
    unittest.main()
