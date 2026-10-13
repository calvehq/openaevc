#!/usr/bin/env python3
"""Architecture enforcement for the OpenAEVC workspace (PLAN §7.17, §54, §56).

Usage: python3 tooling/release-check/check.py [--markers]

Checks:
  * modules of the `openaevc` crate follow the layered graph: no upward or sideways
    references (through paths, grouped imports, aliases, re-exports or `super::` escapes),
    no cycles, and a module behind a feature only reaches modules that feature enables;
  * the `protocol` module stays free of async/storage/HTTP stacks;
  * the published `openaevc` crate depends on no local workspace package;
  * no production dependency on openaevc-testkit or on the `fault-injection` feature;
  * extensions see only the extension contract; the Rust SDK depends on no local package
    but `openaevc`;
  * product vocabulary does not leak into protocol code;
  * with --markers: no unfinished-work markers in production sources.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CRATE = "openaevc"
CRATE_SRC = ROOT / "crates/openaevc/src"

# Layer rank: a module may only reference modules of strictly lower rank,
# or the explicitly listed siblings.
RANK = {
    "protocol": 0,
    "canonical": 1,
    "crypto": 1,
    "core": 2,
    "authority": 3,
    "policy": 3,
    "extension": 3,
    "store": 3,
    "execution": 4,
    "verification": 4,
    "composition": 4,
    "runtime": 5,
    "transport": 6,
}
EXTRA_ALLOWED = {
    # crypto signs canonical bytes.
    ("crypto", "canonical"),
}
# Modules compiled only with the Cargo feature of the same name.
GATED = {"store", "runtime", "transport"}
# Packages that may never be a normal (non-dev) dependency of a production package.
TEST_ONLY = {"openaevc-testkit"}
TEST_ONLY_FEATURES = {"fault-injection"}
# Third-party stacks forbidden in the protocol module.
PROTOCOL_FORBIDDEN = re.compile(r"\b(tokio|rusqlite|hyper|hyper_util|axum|reqwest)::")
# Extensions talk to the host over the contract only.
EXTENSION_FORBIDDEN_MODULES = ("store", "runtime", "transport", "execution", "verification", "composition")
EXTENSION_FORBIDDEN = re.compile(r"\bopenaevc::(" + "|".join(EXTENSION_FORBIDDEN_MODULES) + r")\b")
EXTENSION_FORBIDDEN_FEATURES = {"store", "runtime", "transport", "full", "fault-injection"}
SDK = "openaevc-sdk"
PRODUCTION_ROOTS = ("crates/", "bins/", "extensions/", "sdk/rust/")

VOCAB = re.compile(r"\bdraft\b|pull[ -]request|\bbranch(es)?\b|project sidebar|review screen", re.I)
MARKERS = re.compile(
    r"\bTODO\b|\bFIXME\b|unimplemented!\s*\(|todo!\s*\(|panic!\(\s*\"not implemented|\bplaceholder\b|\bstub\b",
    re.I,
)
CRATE_PATH = re.compile(r"(?<![$\w])crate::(\w+)")
CRATE_GROUP = re.compile(r"(?<![$\w])crate::\{")
SUPER_CHAIN = re.compile(r"(?<![\w:])((?:super::)+)(\w+)")


def strip_test_modules(src):
    """Drop `#[cfg(test)]` items: test code may exercise forbidden patterns."""
    idx = src.find("#[cfg(test)]")
    return src if idx < 0 else src[:idx]


def module_depth(rel):
    """Depth below the crate root of the module a file defines (`src/<m>/mod.rs` is 1)."""
    parts = list(rel.parts)
    if parts[-1] == "mod.rs":
        parts.pop()
    else:
        parts[-1] = parts[-1][:-3]
    return len(parts)


def group_heads(src, start):
    """Top-level path heads of the `{...}` group opening at `start`."""
    heads, depth, i, expect = [], 0, start, True
    while i < len(src):
        c = src[i]
        if c == "{":
            depth += 1
            expect = depth == 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1:
            expect = True
        elif expect and depth == 1 and (c.isalpha() or c == "_"):
            m = re.match(r"\w+", src[i:])
            heads.append(m.group(0))
            i += len(m.group(0))
            expect = False
            continue
        i += 1
    return [h for h in heads if h != "self"]


def module_refs(src, depth):
    """Top-level modules of the crate referenced by a source file at `depth`."""
    refs = set(CRATE_PATH.findall(src))
    for m in CRATE_GROUP.finditer(src):
        refs.update(group_heads(src, m.end() - 1))
    # ponytail: `super::` depth ignores inline `mod x { .. }` nesting; files only.
    for m in SUPER_CHAIN.finditer(src):
        if m.group(1).count("super::") == depth:
            refs.add(m.group(2))
    return refs & set(RANK)


def crate_edges(src_dir=CRATE_SRC):
    edges = set()
    for d in sorted(p for p in src_dir.iterdir() if p.is_dir()):
        for f in sorted(d.rglob("*.rs")):
            body = strip_test_modules(f.read_text())
            for t in module_refs(body, module_depth(f.relative_to(src_dir))):
                if t != d.name:
                    edges.add((d.name, t))
    return edges


def feature_closure(features, start):
    seen, todo = set(), [start]
    while todo:
        f = todo.pop()
        if f in seen or f not in features:
            continue
        seen.add(f)
        todo += [x for x in features[f] if ":" not in x and "/" not in x]
    return seen


def find_cycle(edges):
    graph = {}
    for a, b in edges:
        graph.setdefault(a, []).append(b)
    state = {}

    def visit(n, stack):
        state[n] = 1
        for m in graph.get(n, []):
            if state.get(m) == 1:
                return stack[stack.index(m):] + [m]
            if m not in state:
                c = visit(m, stack + [m])
                if c:
                    return c
        state[n] = 2
        return None

    for n in sorted(graph):
        if n not in state:
            c = visit(n, [n])
            if c:
                return c
    return None


def module_violations(edges, features):
    out = []
    for a, b in sorted(edges):
        if a not in RANK or b not in RANK:
            continue
        if (a, b) not in EXTRA_ALLOWED and RANK[b] >= RANK[a]:
            out.append(f"{a} -> {b}: reference points upward or sideways in the layer graph")
        if b in GATED and (a not in GATED or b not in feature_closure(features, a)):
            out.append(f"{a} -> {b}: module `{b}` needs feature `{b}`, which `{a}` does not enable")
    cycle = find_cycle(edges)
    if cycle:
        out.append("module cycle: " + " -> ".join(cycle))
    return out


def protocol_violations(src_dir=CRATE_SRC):
    out = []
    for f in sorted((src_dir / "protocol").rglob("*.rs")):
        for no, line in enumerate(strip_test_modules(f.read_text()).splitlines(), 1):
            if PROTOCOL_FORBIDDEN.search(line):
                out.append(f"{f.relative_to(ROOT)}:{no}: protocol must stay free of async/storage/HTTP")
    return out


def dependency_violations(metadata):
    out = []
    for pkg in metadata["packages"]:
        name = pkg["name"]
        for dep in pkg["dependencies"]:
            d, kind, feats = dep["name"], dep.get("kind"), set(dep.get("features", []))
            local = dep.get("path") is not None
            if name == CRATE and local:
                out.append(f"{name} -> {d}: the published crate must not depend on local packages")
            if kind == "dev":
                continue
            if d in TEST_ONLY and name not in TEST_ONLY:
                out.append(f"{name} -> {d}: production packages must not depend on test-only packages")
            if d == CRATE and feats & TEST_ONLY_FEATURES:
                out.append(f"{name} -> {d}: test-only features in a normal dependency")
            if name.startswith("openaevc-ext-") and d == CRATE and feats & EXTENSION_FORBIDDEN_FEATURES:
                out.append(f"{name} -> {d}: extensions must only use the extension contract")
            if name == SDK and local and d != CRATE:
                out.append(f"{name} -> {d}: the SDK may only depend on the public `openaevc` crate")
    return out


def extension_source_violations(path, src):
    return [
        f"{path}:{no}: extensions must only use the extension contract"
        for no, line in enumerate(src.splitlines(), 1)
        if EXTENSION_FORBIDDEN.search(line)
    ]


def text_violations(src, path, markers=True):
    body = strip_test_modules(src)
    out = []
    for no, line in enumerate(body.splitlines(), 1):
        if VOCAB.search(line):
            out.append(f"{path}:{no}: product vocabulary: {line.strip()}")
        if markers and MARKERS.search(line):
            out.append(f"{path}:{no}: unfinished-work marker: {line.strip()}")
    return out


def main(argv):
    markers = "--markers" in argv
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT))
    crate = next(p for p in meta["packages"] if p["name"] == CRATE)
    problems = dependency_violations(meta)
    problems += module_violations(crate_edges(), crate["features"])
    problems += protocol_violations()
    for f in sorted((ROOT / "extensions").glob("**/src/**/*.rs")):
        problems += extension_source_violations(f.relative_to(ROOT), f.read_text())
    for root in PRODUCTION_ROOTS:
        for f in sorted((ROOT / root).glob("**/src/**/*.rs")):
            if "/tests/" in f.as_posix():
                continue
            problems += text_violations(f.read_text(), f.relative_to(ROOT), markers)
    for p in problems:
        print(p)
    print(f"architecture check: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
