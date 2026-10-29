from __future__ import annotations

import ast
import builtins
import copy
import importlib.machinery
import importlib.util
import io
import json
import sys
from pathlib import Path

import yaml


class ImportDeclarations(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        if node.name != "create_srclang_decl":
            return node
        return self.generic_visit(node)

    def visit_BinOp(self, node):
        self.generic_visit(node)
        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.right, ast.Constant)
            and node.right.value == ")"
            and isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Attribute)
            and node.left.func.attr == "rstrip"
            and isinstance(node.left.func.value, ast.Name)
            and node.left.func.value.id == "field_decl"
        ):
            node.right = ast.Constant(");")
        if (
            isinstance(node.op, ast.Add)
            and isinstance(node.right, ast.Constant)
            and node.right.value == ""
        ):
            left = node.left
            if (
                isinstance(left, ast.BinOp)
                and isinstance(left.right, ast.Call)
                and isinstance(left.right.func, ast.Attribute)
                and left.right.func.attr == "get_srclang_type_name"
            ):
                node.right = ast.Constant(" ")
        return node

    def visit_AugAssign(self, node):
        if (
            isinstance(node.target, ast.Name)
            and node.target.id == "cur_size"
            and isinstance(node.op, ast.Add)
            and isinstance(node.value, ast.Name)
            and node.value.id == "field_size"
        ):
            return ast.copy_location(
                ast.Assign(
                    targets=[node.target],
                    value=ast.BinOp(
                        left=ast.Name(id="offset", ctx=ast.Load()),
                        op=ast.Add(),
                        right=node.value,
                    ),
                ),
                node,
            )
        return node

    def visit_Subscript(self, node):
        self.generic_visit(node)
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "field_decl"
            and isinstance(node.slice, ast.Slice)
        ):
            upper = node.slice.upper
            if (
                isinstance(upper, ast.UnaryOp)
                and isinstance(upper.op, ast.USub)
                and isinstance(upper.operand, ast.Constant)
                and upper.operand.value == 2
            ):
                return ast.copy_location(
                    ast.Call(
                        func=ast.Attribute(
                            value=node.value, attr="rstrip", ctx=ast.Load()
                        ),
                        args=[ast.Constant(",")],
                        keywords=[],
                    ),
                    node,
                )
        return node


class ScriptLoader(importlib.machinery.SourceFileLoader):
    defer_entry = True

    def get_code(self, fullname):
        tree = ast.parse(Path(self.path).read_text(encoding="utf-8"), self.path)
        if self.defer_entry:
            tree.body = [
                node
                for node in tree.body
                if not (
                    isinstance(node, ast.Expr)
                    and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in ("run", "load_data", "print")
                )
            ]
        tree = ImportDeclarations().visit(tree)
        return compile(ast.fix_missing_locations(tree), self.path, "exec")


def load_script(path, documents, defer_entry=True):
    path = Path(path).resolve()

    def open_document(file, mode="r", *args, **kwargs):
        resolved = Path(file).resolve()
        if resolved in documents:
            if mode not in ("r", "rt"):
                raise ValueError("生成数据只允许读取")
            return io.StringIO(
                yaml.safe_dump(documents[resolved], allow_unicode=True, sort_keys=False)
            )
        return builtins.open(file, mode, *args, **kwargs)

    loader = ScriptLoader("ffcs_generated_import", str(path))
    loader.defer_entry = defer_entry
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(loader.name, loader)
    )
    module.open = open_document
    previous = list(sys.path)
    try:
        sys.path.insert(0, str(path.parent))
        loader.exec_module(module)
    finally:
        sys.path[:] = previous
    return module.__dict__


def rebase_data(data, image_base):
    result = copy.deepcopy(data)
    delta = image_base - result["_crossclient"]["image_base"]
    for category in ("globals", "functions"):
        result[category] = {
            int(address) + delta: name
            for address, name in (result.get(category) or {}).items()
        }
    for definition in result.get("classes", {}).values():
        if not definition:
            continue
        if "funcs" in definition:
            definition["funcs"] = {
                int(address) + delta: name
                for address, name in (definition["funcs"] or {}).items()
            }
        for category in ("vtbls", "instances"):
            for item in definition.get(category, []) or []:
                if item["ea"]:
                    item["ea"] += delta
    result["_crossclient"]["image_base"] = image_base
    for resolved in result["_crossclient"].get("resolved_signatures", {}).values():
        resolved["match"] += delta
        resolved["address"] += delta
    if "resolved_statics" in result["_crossclient"]:
        result["_crossclient"]["resolved_statics"] = {
            key: address + delta
            for key, address in result["_crossclient"]["resolved_statics"].items()
        }
    return result


def verify_target(manifest):
    import ida_nalt

    digest = ida_nalt.retrieve_input_file_sha256()
    if not digest or digest.hex() != manifest["target_sha256"]:
        raise ValueError("生成数据与当前 IDA 数据库的输入文件不匹配")


def normalize_primary_bases(definitions, classes):
    virtual = {
        definition.type
        for definition in definitions.structs
        if definition.virtual_functions is not None
        or any(
            member.name == "_vtable" and member.offset == 0
            for member in definition.fields
        )
        or (classes.get(definition.type) or {}).get("vtbls")
    }
    while True:
        inherited = {
            definition.type
            for definition in definitions.structs
            if definition.type not in virtual
            and any(
                member.base and member.offset == 0 and member.type in virtual
                for member in definition.fields
            )
        }
        if not inherited:
            break
        virtual.update(inherited)
    for definition in definitions.structs:
        if definition.union or definition.type not in virtual:
            continue
        if any(member.base and member.offset == 0 for member in definition.fields):
            continue
        candidates = [
            member
            for member in definition.fields
            if member.offset == 0
            and member.type in virtual
            and not hasattr(member, "size")
        ]
        if len(candidates) == 1:
            candidates[0].base = True


def configure_native(api, manifest, image_base):
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import ida_typeinf

    resolved = manifest["resolved_signatures"]
    delta = image_base - manifest["image_base"]
    read_yaml = api.get_yaml
    preprocess = api.preprocess_yaml

    def get_yaml():
        definitions = read_yaml()
        for definition in definitions.structs:
            for member in definition.fields:
                if hasattr(member, "return_type"):
                    member.type = "__fastcall"
        return definitions

    api.get_yaml = get_yaml

    def preprocess_yaml(definitions):
        if api.srclang_importer:
            for definition in definitions.structs:
                if definition.union or definition.virtual_functions is not None:
                    continue
                info = ida_typeinf.tinfo_t()
                if not info.get_named_type(
                    None, api.clean_struct_name(definition.type)
                ):
                    continue
                members = ida_typeinf.udt_type_data_t()
                if info.get_udt_details(members) and any(
                    member.offset == 0 and member.is_vftable() for member in members
                ):
                    definition.virtual_functions = []
        normalize_primary_bases(definitions, (api.data_yaml or {}).get("classes", {}))
        preprocess(definitions)

    api.preprocess_yaml = preprocess_yaml
    api.get_func_ea_by_sig = lambda signature: (
        resolved[signature]["address"] + delta
        if signature in resolved and resolved[signature]["function"]
        else ida_idaapi.BADADDR
    )

    def function_type(member):
        function = ida_typeinf.func_type_data_t()
        function.cc = ida_typeinf.CM_CC_FASTCALL
        function.rettype = api.get_tinfo_from_type(member.return_type)
        for parameter in member.parameters:
            argument = ida_typeinf.funcarg_t()
            argument.type = api.get_tinfo_from_type(parameter.type)
            argument.name = parameter.name
            function.push_back(argument)
        type_info = ida_typeinf.tinfo_t()
        if not type_info.create_func(function):
            raise RuntimeError(f"无法创建函数类型：{member.name}")
        return type_info

    def apply_function(member, definition, target):
        if target in (0, ida_idaapi.BADADDR):
            return
        if not ida_typeinf.apply_tinfo(
            target, function_type(member), ida_typeinf.TINFO_DEFINITE
        ):
            raise RuntimeError(f"无法应用函数类型：{definition.type}.{member.name}")

    def create_vtable(definition):
        name = api.clean_struct_name(definition.type) + "_vtbl"
        table = ida_typeinf.tinfo_t()
        if not table.get_named_type(None, name):
            raise RuntimeError(f"找不到虚表类型：{name}")
        members = ida_typeinf.udt_type_data_t()
        if not table.get_udt_details(members):
            raise RuntimeError(f"无法读取虚表成员：{name}")
        existing = {}
        for member in members:
            if member.is_gap() or (
                member.name.startswith("gap") and member.type.is_array()
            ):
                continue
            if member.offset % 64 or member.size != 64:
                raise RuntimeError(f"虚表成员未按槽位排列：{name}.{member.name}")
            existing[member.offset // 8] = ida_typeinf.udm_t(member)
        functions = {
            member.offset: member
            for member in definition.virtual_functions
            if member is not None
        }
        size = max(
            definition.vtable_size or 0,
            members.total_size,
            max(functions, default=-8) + 8,
        )
        if size % 8 or any(offset < 0 or offset % 8 for offset in functions):
            raise RuntimeError(f"虚表大小或函数偏移未按槽位对齐：{name}")
        slots = []
        for offset in range(0, size, 8):
            member = existing.get(offset)
            if member is None:
                member = ida_typeinf.udm_t()
                member.offset = offset * 8
                member.size = 64
                member.type = api.get_tinfo_from_type("__int64")
                member.name = (
                    api.get_fallback_vfunc_name(definition.type, offset // 8)
                    or f"vf{offset // 8}"
                )
            function = functions.get(offset)
            if function is not None:
                member.name = function.name
                if function.return_type is not None and function.parameters is not None:
                    pointer = ida_typeinf.tinfo_t()
                    if not pointer.create_ptr(function_type(function)):
                        raise RuntimeError(
                            f"无法创建虚函数指针：{name}.{function.name}"
                        )
                    member.type = pointer
            slots.append(member)
        reserved = {member.name for member in slots}
        used = set()
        members.clear()
        for index, member in enumerate(slots):
            if member.name in used:
                unique = f"{member.name}_vf{index}"
                while unique in reserved or unique in used:
                    unique += "_"
                member.name = unique
            used.add(member.name)
            members.push_back(member)
        members.total_size = size
        members.unpadded_size = size
        members.set_vftable()
        result = ida_typeinf.tinfo_t()
        if not result.create_udt(members, ida_typeinf.BTF_STRUCT):
            raise RuntimeError(f"无法创建虚表类型：{name}")
        error = result.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
        if error != ida_typeinf.TERR_OK:
            raise RuntimeError(
                f"无法保存虚表类型：{name}：{ida_typeinf.tinfo_errstr(error)}"
            )

    def update_member(member, definition):
        apply_function(member, definition, api.get_func_ea_by_sig(member.signature))

    def get_virtual(class_name, offset):
        table = api.get_vft_from_data(class_name)
        if not table or not table.get("ea"):
            return ida_idaapi.BADADDR
        return ida_bytes.get_qword(table["ea"] + offset)

    def update_virtual(member, definition):
        target = get_virtual(definition.type, member.offset)
        if target in (0, ida_idaapi.BADADDR):
            return
        function = ida_funcs.get_func(target)
        if function is None or function.start_ea != target:
            print(
                f"跳过虚函数类型：{definition.type}.{member.name}，"
                f"槽位 {member.offset // 8} 的目标 {target:#x} 不是已识别的函数入口"
            )
            return
        name = ida_funcs.get_func_name(target)
        if name is not None:
            for prefix in ("j_", "thunk_"):
                name = name.removeprefix(prefix)
        if name != "_purecall":
            apply_function(member, definition, target)

    def update_static(member, definition):
        key = member.signature + "|" + ",".join(map(str, member.relative_offsets))
        if key not in manifest["resolved_statics"]:
            return
        target = manifest["resolved_statics"][key] + delta
        type_info = api.get_tinfo_from_type(member.return_type)
        if member.is_pointer:
            pointer = ida_typeinf.tinfo_t()
            pointer.create_ptr(type_info)
            type_info = pointer
        if not ida_typeinf.apply_tinfo(target, type_info, ida_typeinf.TINFO_DEFINITE):
            raise RuntimeError(f"无法应用静态成员类型：{definition.type}.{member.name}")

    api.update_static_member = update_static
    api.create_vtable = create_vtable
    api.update_member_func = update_member
    api.get_vfunc_ea_from_data = get_virtual
    api.update_virt_func = update_virtual


def import_expansion(payload, data, directory, image_base):
    import ida_typeinf

    own = set(payload["expansion_types"]) | set(payload["generated_types"])
    definitions = copy.deepcopy(payload)
    documents = {
        directory / "data.yml": data,
        directory / "ffxiv_structs.yml": definitions,
    }
    module = load_script(directory / "ffxiv_structimporter.py", documents)
    api = module["api"]
    configure_native(api, payload, image_base)
    reused = {
        definition["type"]
        for definition in definitions["structs"]
        if definition["type"] not in own
        and ida_typeinf.tinfo_t().get_named_type(
            None, api.clean_struct_name(definition["type"])
        )
    }
    reused.update(
        definition["type"]
        for definition in definitions["enums"]
        if definition["type"] not in payload["expansion_enums"]
        and ida_typeinf.tinfo_t().get_named_type(None, definition["type"])
    )
    if api.srclang_importer:
        for definition in definitions["structs"]:
            if definition["type"] not in reused:
                name = api.clean_struct_name(definition["type"])
                api.srclang_types[name] = api.generate_hashed_type_name(name)
    for name in (
        "delete_struct",
        "create_struct_members",
        "create_vtable",
        "create_union",
        "update_member_func",
        "update_static_member",
        "update_virt_func",
        "delete_enum",
        "create_enum_struct",
    ):
        original = getattr(api, name)

        def scoped(*arguments, original=original):
            if arguments[-1].type not in reused:
                return original(*arguments)

        setattr(api, name, scoped)
    create = api.create_struct
    finalise = api.finalise_struct
    pending = {}

    def create_struct(definition):
        if definition.type in reused and not api.srclang_importer:
            return
        if api.srclang_importer:
            pending[definition.type] = definition
        create(definition)

    def finalise_struct(definition):
        if definition.type in reused and not api.srclang_importer:
            return
        finalise(definition)
        pending.pop(definition.type, None)

    api.create_struct = create_struct
    api.finalise_struct = finalise_struct
    try:
        module["run"]()
    finally:
        for definition in pending.values():
            finalise(definition)
    for definition in definitions["structs"]:
        if definition["type"] in reused:
            continue
        info = ida_typeinf.tinfo_t()
        type_name = api.clean_struct_name(definition["type"])
        if not info.get_named_type(None, type_name):
            raise RuntimeError(f"导入后缺少结构：{definition['type']}")
        members = ida_typeinf.udt_type_data_t()
        if not info.get_udt_details(members):
            continue
        fields = {field["name"]: field for field in definition["fields"]}
        changed = False
        for member in members:
            field = fields.get(member.name)
            if field is None:
                continue
            notes = [field["comment"]] if field.get("comment") else []
            for bit in field.get("bits", []):
                if "arguments" in bit:
                    name, start, length = bit["arguments"]
                else:
                    name, start, length = bit["name"], bit["offset"], bit["size"]
                notes.append(
                    f"{name}：第 {start} 位起，共 {length} 位，类型 {bit['type']}"
                )
            if notes:
                member.cmt = "\n".join(notes)
                changed = True
        if changed:
            info.create_udt(
                members,
                ida_typeinf.BTF_UNION
                if definition["union"]
                else ida_typeinf.BTF_STRUCT,
            )
            if (
                info.set_named_type(None, type_name, ida_typeinf.NTF_REPLACE)
                != ida_typeinf.TERR_OK
            ):
                raise RuntimeError(f"无法保存成员说明：{definition['type']}")


def run(data_path=None, expansion_path=None):
    import ida_auto
    import ida_idaapi
    import ida_kernwin
    import ida_nalt
    import ida_name

    directory = Path(__file__).resolve().parent
    if data_path is None and expansion_path is None:
        data_path = ida_kernwin.ask_file(
            False, "*.yml", "选择为当前客户端生成的命名数据"
        )
        if not data_path:
            return
    payload = None
    if expansion_path is not None:
        payload = json.loads(Path(expansion_path).read_text(encoding="utf-8"))
        verify_target(payload)
    if data_path is not None:
        data = yaml.safe_load(Path(data_path).read_text(encoding="utf-8"))
        if "_crossclient" not in data:
            raise ValueError("请选择跨客户端工具生成的命名数据")
        verify_target(data["_crossclient"])
    else:
        data = copy.deepcopy(payload["data"])
    image_base = ida_nalt.get_imagebase()
    data = rebase_data(data, image_base)
    if payload is not None and data_path is not None:
        extra = rebase_data(payload["data"], image_base)
        for name, definition in extra["classes"].items():
            existing = data["classes"].setdefault(name, {}) or {}
            existing.setdefault("funcs", {}).update(definition.get("funcs", {}))
            if definition.get("vtbls"):
                existing["vtbls"] = definition["vtbls"]
            if definition.get("instances"):
                existing["instances"] = definition["instances"]
            data["classes"][name] = existing
    if payload is not None:
        for definition in payload["structs"]:
            if definition["type"] not in payload[
                "expansion_types"
            ] or not definition.get("virtual_functions"):
                continue
            cls = data["classes"].setdefault(definition["type"], {})
            cls["vfuncs"] = {
                function["offset"] // 8: function["name"]
                for function in definition["virtual_functions"]
            }
            if not cls.get("vtbls"):
                table = ida_name.get_name_ea(
                    ida_idaapi.BADADDR, "vtbl_" + definition["type"]
                )
                if table != ida_idaapi.BADADDR:
                    cls["vtbls"] = [{"ea": table}]
    documents = {directory / "data.yml": data}
    ida_auto.auto_wait()
    rename = load_script(directory / "ffxiv_idarename.py", documents)
    rename["FfxivClass"].STANDARD_IMAGE_BASE = image_base
    rename["load_data"]()
    if payload is None:
        importer = load_script(directory / "ffxiv_structimporter.py", documents)
        if not importer["api"].can_run():
            load_script(directory / "ffxiv_exdgetters.py", documents, defer_entry=False)
        configure_native(importer["api"], data["_crossclient"], image_base)
        importer["run"]()
    else:
        import_expansion(payload, data, directory, image_base)
    ida_auto.auto_wait()
    print("生成数据导入完成")


if __name__ == "__main__":
    run()
