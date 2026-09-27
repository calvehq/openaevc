"""Requirement coverage: every MUST ID in spec/ is verified by at least one conformance case,
and every ID a case cites exists in the spec."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFINED = re.compile(r"^\*\*(AEVC-[A-Z]+-\d{4})\*\*", re.M)
CITED = re.compile(r'"(AEVC-[A-Z]+-\d{4})"')


def spec_ids(spec_dir):
    ids = set()
    for p in sorted(Path(spec_dir).glob("*.md")):
        if p.name != "README.md":
            ids |= set(DEFINED.findall(p.read_text()))
    return ids


def case_ids(sources):
    return {i for s in sources for i in CITED.findall(Path(s).read_text())}


def problems(spec, cited):
    return [f"{i}: no conformance case verifies it" for i in sorted(spec - cited)] + [
        f"{i}: cited by a case but not defined in spec/" for i in sorted(cited - spec)
    ]


def main():
    src = ROOT / "crates/openaevc-conformance/src"
    spec = spec_ids(ROOT / "spec")
    found = problems(spec, case_ids([src / "cases/mod.rs", src / "extension_target.rs"]))
    for p in found:
        print(p)
    print(f"{len(spec)} requirements, {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
