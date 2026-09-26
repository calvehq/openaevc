"""Self-test for check.py: the checks must reject the violations they exist for."""
import json
import unittest
from pathlib import Path

import check

HERE = Path(__file__).parent


def meta(edges):
    names = sorted({n for e in edges for n in e[:2]})
    pkgs = []
    for n in names:
        deps = [{"name": b, "kind": k} for a, b, k in edges if a == n]
        pkgs.append({"name": n, "dependencies": deps, "manifest_path": f"/x/{n}/Cargo.toml"})
    return {"packages": pkgs}


class DependencyRules(unittest.TestCase):
    def test_allowed_graph_passes(self):
        m = meta([("openaevc-core", "openaevc-protocol", None),
                  ("openaevc-runtime", "openaevc-core", None),
                  ("openaevc-runtime", "openaevc-testkit", "dev")])
        self.assertEqual(check.dependency_violations(m), [])

    def test_lower_crate_on_runtime_fails(self):
        m = meta([("openaevc-store", "openaevc-runtime", None)])
        self.assertTrue(check.dependency_violations(m))

    def test_production_dep_on_testkit_fails(self):
        m = meta([("openaevc-runtime", "openaevc-testkit", None)])
        self.assertTrue(check.dependency_violations(m))

    def test_protocol_on_tokio_fails(self):
        m = meta([("openaevc-protocol", "tokio", None)])
        self.assertTrue(check.dependency_violations(m))

    def test_extension_on_store_fails(self):
        m = meta([("openaevc-ext-reference-kv", "openaevc-store", None)])
        self.assertTrue(check.dependency_violations(m))


class TextRules(unittest.TestCase):
    def test_vocabulary_and_markers_detected(self):
        self.assertTrue(check.text_violations("fn a() { /* open a pull request */ }", "x.rs"))
        self.assertTrue(check.text_violations("fn a() { t" + "odo!() }", "x.rs"))
        self.assertEqual(check.text_violations("fn a() {}", "x.rs"), [])

    def test_test_modules_are_exempt(self):
        src = "fn a() {}\n#[cfg(test)]\nmod tests { fn b() { un" + "implemented!() } }\n"
        self.assertEqual(check.text_violations(src, "x.rs"), [])


if __name__ == "__main__":
    unittest.main()
