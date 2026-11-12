from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

from send2trash import send2trash

from ffxiv_crossclient import Image, write_json
from ffxiv_client_update import locate


def ida_call(url, name, arguments):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    if raw.startswith("event:") or raw.startswith("data:"):
        raw = next(line[6:] for line in raw.splitlines() if line.startswith("data: "))
    result = json.loads(raw)
    if "error" in result:
        raise ValueError(result["error"])
    return result["result"]


def signature_value(result):
    if isinstance(result, dict):
        if result.get("isError"):
            raise ValueError(result)
        for key in ("signature", "pattern"):
            value = result.get(key)
            if isinstance(value, str):
                return value
        for value in result.values():
            found = signature_value(value)
            if found is not None:
                return found
    elif isinstance(result, list):
        for value in result:
            found = signature_value(value)
            if found is not None:
                return found
    elif isinstance(result, str) and result.startswith(("{", "[")):
        return signature_value(json.loads(result))
    return None


def prepare_signatures(report, url, deadline):
    target = Image(report["target"])
    if target.sha256 != report["target_sha256"]:
        raise ValueError("目标客户端已发生变化")
    survey = ida_call(url, "survey_binary", {"detail_level": "minimal"})
    metadata = survey.get("structuredContent")
    if metadata is None:
        metadata = json.loads(next(item["text"] for item in survey["content"] if item["type"] == "text"))
    if metadata["metadata"]["sha256"] != target.sha256:
        raise ValueError("IDA 数据库与目标客户端不匹配")
    edits = []
    rejected = []
    responses = {}
    for item in report["signatures"]:
        if item["status"] not in ("target-unresolved", "wrong-target") or item["mapped_match"] is None:
            continue
        if item.get("kind") != "MemberFunction":
            rejected.append({"path": item["path"], "line": item["line"], "reason": "requires-consumer-semantics-review"})
            continue
        if time.monotonic() > deadline:
            raise TimeoutError("特征码生成超过本次时间限制")
        address = item["mapped_match"]
        if address not in responses:
            responses[address] = ida_call(url, "make_signature", {"addrs": hex(address), "format": "x64dbg"})
        result = responses[address]
        signature = signature_value(result)
        if signature is None:
            rejected.append({"path": item["path"], "line": item["line"], "reason": "signature-generation-failed", "response": result})
            continue
        resolved = locate(target, signature)
        if resolved["matches"] != [address - target.base]:
            rejected.append({"path": item["path"], "line": item["line"], "reason": "generated-signature-disagreement", "response": result})
            continue
        edits.append({
            "path": item["path"], "sha256": item["sha256"], "span": item["span"],
            "before": item["signature"], "after": signature, "address": address, "response": result,
        })
    return {"schema": 1, "target_sha256": target.sha256, "edits": edits, "rejected": rejected}


def apply_plan(plan):
    if plan.get("schema") != 1:
        raise ValueError("不支持的修复计划格式")
    changes = defaultdict(list)
    for edit in plan["edits"]:
        changes[Path(edit["path"])].append(edit)
    prepared = {}
    for path, edits in changes.items():
        if path.is_symlink() or path.stat().st_nlink != 1:
            raise ValueError(f"拒绝修改链接文件：{path}")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if any(edit["sha256"] != digest for edit in edits):
            raise ValueError(f"源码已发生变化：{path}")
        text = raw.decode("utf-8-sig")
        boundary = len(text)
        for edit in sorted(edits, key=lambda item: item["span"][0], reverse=True):
            begin, end = edit["span"]
            if not 0 <= begin <= end <= boundary or text[begin:end] != edit["before"]:
                raise ValueError(f"替换范围或原文不匹配：{path}")
            text = text[:begin] + edit["after"] + text[end:]
            boundary = begin
        prepared[path] = text.encode("utf-8")
    if not prepared:
        return 0
    backup = Path(tempfile.mkdtemp(prefix="ffxiv-client-update-"))
    for index, path in enumerate(prepared):
        shutil.copy2(path, backup / f"{index}-{path.name}")
    send2trash(str(backup))
    for path, raw in prepared.items():
        path.write_bytes(raw)
    return len(prepared)


def prepare_layouts(report):
    edits = []
    for definition in report["structures"]:
        path = Path(definition["path"])
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != definition["current_sha256"]:
            raise ValueError(f"源码已发生变化：{path}")
        text = raw.decode("utf-8-sig")
        candidates = [
            (field["current"]["span"], field["candidates"][0], field)
            for field in definition["fields"]
            if field["status"] == "candidate" and len(field["candidates"]) == 1
        ]
        candidates.extend(
            (virtual["current"]["span"], virtual["candidates"][0], virtual)
            for virtual in definition["virtual_slots"]
            if virtual["status"] == "candidate" and len(virtual["candidates"]) == 1 and "current" in virtual
        )
        if definition["size_status"] == "allocation-candidate" and len(definition["size_candidates"]) == 1:
            candidates.append((definition["current_size_span"], definition["size_candidates"][0], definition["size_evidence"]))
        for span, value, evidence in candidates:
            before = text[span[0]:span[1]]
            after = f"0x{value:X}" if before.lower().startswith("0x") else str(value)
            if before != after:
                edits.append({
                    "path": str(path), "sha256": definition["current_sha256"], "span": span,
                    "before": before, "after": after, "evidence": evidence,
                })
    return {"schema": 1, "target_sha256": report["target_sha256"], "edits": edits, "rejected": []}


def main():
    parser = argparse.ArgumentParser(description="从 IDA 原样保存特征码修复计划，或按校验值应用计划")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--ida-url")
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--kind", choices=("signatures", "layouts"), default="signatures")
    args = parser.parse_args()
    if args.apply:
        if args.report or args.ida_url:
            parser.error("应用计划时不能重新生成特征码")
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        print(json.dumps({"changed_files": apply_plan(plan)}, ensure_ascii=False))
        return
    if args.report is None or (args.kind == "signatures" and args.ida_url is None):
        parser.error("生成计划需要 --report；特征码计划还需要 --ida-url")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    protected = {args.report.resolve(), Path(report["source"]).resolve(), Path(report["target"]).resolve()}
    protected.update(Path(item["path"]).resolve() for item in report["signatures"])
    if args.plan.resolve() in protected:
        parser.error("计划路径不得覆盖输入文件")
    if args.kind == "layouts":
        plan = prepare_layouts(report)
    else:
        plan = prepare_signatures(report, args.ida_url, time.monotonic() + 270)
    write_json(args.plan, plan)
    print(json.dumps({"edits": len(plan["edits"]), "rejected": len(plan["rejected"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
