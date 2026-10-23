"""Trusted isolated AST worker. Run with python -I; target text is stdin data."""

from __future__ import annotations

import ast
import json
import os
import sys
import re
import tomllib

_JOB_HANDLE: object = None


def _enforce_limits() -> None:
    global _JOB_HANDLE
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        return
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                           "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class Extended(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Counters), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise OSError("job_object_creation_failed")
    limits = Extended()
    limits.BasicLimitInformation.PerProcessUserTimeLimit = 30 * 10_000_000
    limits.BasicLimitInformation.LimitFlags = 0x2 | 0x100 | 0x2000
    limits.ProcessMemoryLimit = 512 * 1024 * 1024
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise OSError("job_object_limits_unavailable")
    if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
        raise OSError("job_object_assignment_unavailable")
    _JOB_HANDLE = job


def _module(path: str) -> str:
    parts = path[:-3].split("/")
    if parts[0] == "src":
        parts = parts[1:]
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _scalar(node: ast.AST) -> tuple[bool, object]:
    if isinstance(node, ast.Constant) and (node.value is None or type(node.value) in (str, int, float, bool)):
        value = node.value
        if isinstance(value, float) and (value != value or abs(value) == float("inf")):
            return False, None
        return True, value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)) and isinstance(node.operand, ast.Constant):
        value = node.operand.value
        if type(value) in (int, float):
            result = -value if isinstance(node.op, ast.USub) else value
            if type(result) is float and (result != result or abs(result) == float("inf")):
                return False, None
            return True, result
    return False, None


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _collect(path: str, text: str) -> dict[str, object]:
    tree = ast.parse(text, filename=path, type_comments=False)
    raw_source = text.encode("utf-8")
    offsets = [0]
    for line in raw_source.split(b"\n")[:-1]:
        offsets.append(offsets[-1] + len(line) + 1)
    facts: list[dict[str, object]] = []
    flags: list[str] = []
    bindings: dict[str, list[ast.AST]] = {}
    imports: dict[str, tuple[str, str]] = {}
    exports: dict[str, tuple[str, str]] = {}

    def span(node: ast.AST) -> dict[str, int]:
        line = getattr(node, "lineno", None)
        end_line = getattr(node, "end_lineno", None)
        column = getattr(node, "col_offset", None)
        end_column = getattr(node, "end_col_offset", None)
        if not all(type(value) is int for value in (line, end_line, column, end_column)):
            raise ValueError("ast_end_offsets_unavailable")
        return {"start_byte": offsets[line - 1] + column, "end_byte": offsets[end_line - 1] + end_column,
                "start_line": line, "end_line": end_line}

    def add(kind: str, subject: str, key: str | None, value: object, node: ast.AST) -> None:
        facts.append(dict(kind=kind, subject=subject, key=key, value=value, path=path, module=_module(path), **span(node)))

    for node in tree.body:
        targets: list[str] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            targets = [node.name]
        elif isinstance(node, ast.Assign):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        elif isinstance(node, ast.Delete):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    flags.append("wildcard_import")
                    continue
                local = alias.asname or alias.name.split(".")[0]
                targets.append(local)
                if isinstance(node, ast.Import):
                    imports[local] = ("module", alias.name)
                else:
                    imported_module = ("." * node.level) + (node.module or "")
                    imports[local] = (imported_module, alias.name)
                    if node.level == 0 and node.module:
                        exports[local] = (node.module, alias.name)
        for target in targets:
            bindings.setdefault(target, []).append(node)

    flags.extend(f"shadowed:{name}" for name, nodes in bindings.items() if len(nodes) > 1)
    exports = {name: target for name, target in exports.items() if len(bindings.get(name, [])) == 1}

    dynamic_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in tree.body:
            if (isinstance(node, ast.Import) and any(alias.name == "os" for alias in node.names)) or (isinstance(node, ast.ImportFrom) and node.module == "os"):
                flags.append("unresolved_env_binding")
        if isinstance(node, ast.Call) and _name(node.func) in {"exec", "eval", "globals", "locals", "setattr", "__import__"}:
            flags.append("dynamic_namespace")
        if isinstance(node, (ast.If, ast.Try, ast.For, ast.While, ast.With, ast.Match)):
            # Conservative module-wide coverage flag; direct positive declarations
            # stay syntactic facts, but absence cannot ignore conditional bindings.
            if node in tree.body:
                flags.append("conditional_module_bindings")
                for child in ast.walk(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        dynamic_names.add(child.name)

    def declared(node: ast.AST, subject: str) -> None:
        add("symbol_declared", subject, None, None, node)
        if isinstance(node, ast.AsyncFunctionDef):
            add("bounded_code_fact", subject, "async-def/v1", True, node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional = list(node.args.posonlyargs) + list(node.args.args)
            for argument, default in zip(positional[-len(node.args.defaults):] if node.args.defaults else [], node.args.defaults):
                literal, value = _scalar(default)
                if literal:
                    add("bounded_code_fact", subject, f"literal-default/v1:{argument.arg}", value, default)
            for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                if default is not None:
                    literal, value = _scalar(default)
                    if literal:
                        add("bounded_code_fact", subject, f"literal-default/v1:{argument.arg}", value, default)
            # Nested declarations are excluded from a function's explicit-raise scope.
            pending = list(node.body)
            while pending:
                child = pending.pop()
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(child, ast.Raise):
                    exception = _name(child.exc.func) if isinstance(child.exc, ast.Call) else (_name(child.exc) if child.exc else None)
                    if exception:
                        add("bounded_code_fact", subject, f"explicit-raise/v1:{exception}", True, child)
                pending.extend(ast.iter_child_nodes(child))
        for decorator in getattr(node, "decorator_list", []):
            if isinstance(decorator, ast.Call):
                decorator_name = _name(decorator.func)
                if decorator_name:
                    for keyword in decorator.keywords:
                        literal, value = _scalar(keyword.value)
                        if keyword.arg is not None and literal:
                            add("bounded_code_fact", subject, f"decorator-argument/v1:{decorator_name}.{keyword.arg}", value, keyword.value)

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if len(bindings.get(node.name, [])) != 1 or node.name in dynamic_names:
                flags.append(f"shadowed:{node.name}")
                continue
            declared(node, node.name)
            if isinstance(node, ast.ClassDef):
                method_counts: dict[str, int] = {}
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_counts[child.name] = method_counts.get(child.name, 0) + 1
                    elif isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name):
                                method_counts[target.id] = method_counts.get(target.id, 0) + 1
                    elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                        method_counts[child.target.id] = method_counts.get(child.target.id, 0) + 1
                    elif isinstance(child, (ast.If, ast.Try, ast.For, ast.While, ast.With, ast.Match)):
                        flags.append(f"conditional_class_bindings:{node.name}")
                flags.extend(f"shadowed:{node.name}.{name}" for name, count in method_counts.items() if count > 1)
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and method_counts[child.name] == 1:
                        declared(child, f"{node.name}.{child.name}")
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value_node = node.value
            if value_node is None:
                continue
            literal, value = _scalar(value_node)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and len(bindings.get(target.id, [])) == 1:
                    if literal:
                        add("config_literal", target.id, target.id, value, value_node)
                        add("bounded_code_fact", target.id, "literal-constant/v1", value, value_node)
                    else:
                        flags.append(f"dynamic_assignment:{target.id}")

    # The os binding is trusted only when it has exactly one direct module binding
    # and no local assignment/import/function parameter shadows it in any scope.
    for node in ast.walk(tree):
        key_node: ast.AST | None = None
        alias: str | None = None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = _name(node.func)
            if name and node.args:
                prefix, _, member = name.rpartition(".")
                if member == "getenv" and imports.get(prefix) == ("module", "os"):
                    alias, key_node = prefix, node.args[0]
                elif member == "get" and prefix.endswith(".environ"):
                    candidate = prefix[:-8]
                    if imports.get(candidate) == ("module", "os"):
                        alias, key_node = candidate, node.args[0]
                elif member == "get" and imports.get(prefix) == ("os", "environ"):
                    alias, key_node = prefix, node.args[0]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.args:
            if imports.get(node.func.id) == ("os", "getenv"):
                alias, key_node = node.func.id, node.args[0]
        elif isinstance(node, ast.Subscript):
            name = _name(node.value)
            if name and name.endswith(".environ") and imports.get(name[:-8]) == ("module", "os"):
                alias, key_node = name[:-8], node.slice
            elif name and imports.get(name) == ("os", "environ"):
                alias, key_node = name, node.slice
        if alias and isinstance(key_node, ast.Constant) and type(key_node.value) is str:
            rebound = len(bindings.get(alias, [])) != 1
            for child in ast.walk(tree):
                if isinstance(child, ast.Name) and child.id == alias and isinstance(child.ctx, (ast.Store, ast.Del)):
                    rebound = True
                if isinstance(child, ast.arg) and child.arg == alias:
                    rebound = True
            if rebound or "dynamic_namespace" in flags:
                flags.append("shadowed_env_binding")
            else:
                add("env_reference", key_node.value, None, None, node)
    return {"facts": facts, "flags": sorted(set(flags)), "exports": exports}


def _collect_toml(path: str, text: str) -> dict[str, object]:
    value = tomllib.loads(text)
    raw = text.encode("utf-8")
    coordinates = {"start_byte": 0, "end_byte": len(raw), "start_line": 1,
                   "end_line": max(1, raw.count(b"\n") + (0 if raw.endswith(b"\n") else 1))}
    facts: list[dict[str, object]] = []
    flags: list[str] = []

    def add(kind: str, subject: str, key: str | None, item: object) -> None:
        facts.append(dict(kind=kind, subject=subject, key=key, value=item, path=path, module=None, **coordinates))

    def walk(item: dict[str, object], prefix: str = "") -> None:
        for key, child in item.items():
            dotted = f"{prefix}.{key}" if prefix else key
            if type(child) in (str, int, float, bool):
                if type(child) is float and (child != child or abs(child) == float("inf")):
                    flags.append(f"dynamic_assignment:{dotted}")
                else:
                    add("config_literal", dotted, dotted, child)
            elif type(child) is dict:
                walk(child, dotted)
    walk(value)
    project = value.get("project", {})
    if type(project) is not dict:
        flags.append("invalid_project_table")
        return {"facts": facts, "flags": flags, "exports": {}}
    for name in ("version", "requires-python", "license"):
        if type(project.get(name)) is str:
            add("metadata_declared", name, name, project[name])
        elif name in project:
            flags.append(f"dynamic_metadata:{name}")
    dynamic = project.get("dynamic", [])
    if type(dynamic) is list:
        flags.extend(f"dynamic_metadata:{name}" for name in dynamic if type(name) is str)
    dependencies = project.get("dependencies", [])
    if type(dependencies) is not list:
        flags.append("dynamic_metadata:dependencies")
    else:
        for dependency in dependencies:
            if type(dependency) is not str:
                flags.append("invalid_dependency_literal")
                continue
            matched = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(.*)", dependency.strip())
            if not matched:
                flags.append("invalid_dependency_literal")
                continue
            name = re.sub(r"[-_.]+", "-", matched.group(1)).lower()
            add("dependency_declared", name, None, matched.group(2).strip())
    scripts = project.get("scripts", {})
    if type(scripts) is dict:
        for name, target in scripts.items():
            if type(target) is str:
                add("cli_entry_declared", name, name, target)
            else:
                flags.append("dynamic_cli_mapping")
    return {"facts": facts, "flags": sorted(set(flags)), "exports": {}}


def main() -> None:
    try:
        _enforce_limits()
    except Exception as error:
        print(json.dumps({"enforced": False, "error": str(error), "files": []}))
        return
    raw = sys.stdin.buffer.read(24 * 1024 * 1024 + 1)
    if len(raw) > 24 * 1024 * 1024:
        raise ValueError("parser_input_limit")
    value = json.loads(raw)
    if type(value) is not list or len(value) > 5000:
        raise ValueError("invalid_worker_packet")
    output = []
    for item in value:
        if type(item) is not dict or set(item) != {"path", "text"} or type(item["path"]) is not str or type(item["text"]) is not str:
            raise ValueError("invalid_worker_file")
        try:
            result = _collect_toml(item["path"], item["text"]) if item["path"] == "pyproject.toml" else _collect(item["path"], item["text"])
            output.append(dict(path=item["path"], error=None, **result))
        except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
            output.append(dict(path=item["path"], error=type(error).__name__, facts=[], flags=[], exports={}))
    print(json.dumps({"enforced": True, "error": None, "files": output}, ensure_ascii=False, allow_nan=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
