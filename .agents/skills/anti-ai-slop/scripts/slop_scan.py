#!/usr/bin/env python3
"""Scan Python runtime string literals for AI-writing tells.

Docstrings and comments are excluded on purpose: they are internal prose,
dense with load-bearing source anchors, and cleaning them is churn. Only
strings a user can see at runtime (exceptions, log messages) matter here.

Usage: python slop_scan.py [path ...]    (default: src)
Exit code 1 when hits are found, so it can gate CI or a pre-commit hook.
"""

import ast
import pathlib
import re
import sys

TELLS = re.compile(
    "\\u2014|\\u2013"  # em dash, en dash (escaped so the file itself stays tell-free)
    r"|\bseamless\w*|\bcomprehensive\b|\brobust\b|\beffortless\w*"
    r"|\bpowerful\b|\bsimply\b|\bdelve\b|\bcrucial\b|\bvibrant\b"
    r"|\bLet's\b|\bstreamlin\w+|\bempower\w*|\belevate\b",
    re.IGNORECASE,
)


def docstring_ids(tree: ast.AST) -> set[int]:
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                out.add(id(body[0].value))
    return out


def scan(paths: list[str]) -> int:
    hits = 0
    for root in paths:
        root_path = pathlib.Path(root)
        files = [root_path] if root_path.is_file() else sorted(root_path.rglob("*.py"))
        for path in files:
            try:
                tree = ast.parse(path.read_text())
            except SyntaxError as exc:
                print(f"{path}: unparseable ({exc})", file=sys.stderr)
                continue
            skip = docstring_ids(tree)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and id(node) not in skip
                    and TELLS.search(node.value)
                ):
                    snippet = node.value.replace("\n", "\\n")[:100]
                    print(f"{path}:{node.lineno}: {snippet}")
                    hits += 1
    print(f"-- {hits} runtime string literal(s) with tells")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(scan(sys.argv[1:] or ["src"]))
