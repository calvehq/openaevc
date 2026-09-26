#!/usr/bin/env python3
"""Architecture enforcement for the OpenAEVC workspace (PLAN §7.17, §54, §56).

Usage: python3 tooling/release-check/check.py [--markers]

Checks:
  * crate dependency edges follow the layered graph (no upward edges, no production
    dependency on openaevc-testkit, no async/storage/HTTP stack under openaevc-protocol,
    extensions never see runtime/store crates);
  * product vocabulary does not leak into protocol crates;
  * with --markers: no unfinished-work markers in production sources.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Layer rank: a crate may only depend (normally) on crates of strictly lower rank,
# or on the explicitly listed siblings.
RANK = {
    "openaevc-protocol": 0,
    "openaevc-canonical": 1,
    "openaevc-crypto": 1,
    "openaevc-core": 2,
    "openaevc-authority": 3,
    "openaevc-policy": 3,
    "openaevc-extension-contract": 3,
    "openaevc-store": 3,
    "openaevc-execution": 4,
    "openaevc-verification": 4,
    "openaevc-composition": 4,
    "openaevc-runtime": 5,
    "openaevc-transport": 6,
    "openaevc-sdk": 7,
    "openaevc-conformance": 8,
}
EXTRA_ALLOWED = {
    # crypto signs canonical bytes.
    ("openaevc-crypto", "openaevc-canonical"),
}
# Crates that may never be a normal (non-dev) dependency of a production crate.
TEST_ONLY = {"openaevc-testkit"}
# Third-party stacks forbidden in openaevc-protocol's direct dependencies.
PROTOCOL_FORBIDDEN = {"tokio", "rusqlite", "hyper", "axum", "reqwest", "hyper-util"}
# Extensions talk to the host over the contract only.
EXTENSION_FORBIDDEN = {
    "openaevc-store", "openaevc-runtime", "openaevc-transport", "openaevc-sdk",
    "openaevc-execution", "openaevc-verification", "openaevc-composition", "rusqlite",
}
PRODUCTION_ROOTS = ("crates/", "bins/", "extensions/")

VOCAB = re.compile(r"\bdraft\b|pull[ -]request|\bbranch(es)?\b|project sidebar|review screen", re.I)
MARKERS = re.compile(
    r"\bTODO\b|\bFIXME\b|unimplemented!\s*\(|todo!\s*\(|panic!\(\s*\"not implemented|\bplaceholder\b|\bstub\b",
    re.I,
)


def dependency_violations(metadata):
    out = []
    for pkg in metadata["packages"]:
        name = pkg["name"]
        for dep in pkg["dependencies"]:
            d, kind = dep["name"], dep.get("kind")
            if kind == "dev":
                continue
            if d in TEST_ONLY and name not in TEST_ONLY:
                out.append(f"{name} -> {d}: production crates must not depend on test-only crates")
            if name == "openaevc-protocol" and d in PROTOCOL_FORBIDDEN:
                out.append(f"{name} -> {d}: protocol crate must stay free of async/storage/HTTP")
            if name.startswith("openaevc-ext-") and d in EXTENSION_FORBIDDEN:
                out.append(f"{name} -> {d}: extensions must only use the extension contract")
            if name in RANK and d in RANK and (name, d) not in EXTRA_ALLOWED:
                if RANK[d] >= RANK[name]:
                    out.append(f"{name} -> {d}: dependency points upward or sideways in the layer graph")
    return out


def strip_test_modules(src):
    """Drop `#[cfg(test)]` items: test code may exercise forbidden patterns."""
    idx = src.find("#[cfg(test)]")
    return src if idx < 0 else src[:idx]


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
    problems = dependency_violations(meta)
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
