"""Self-test for check.py: the checks must reject the violations they exist for."""
import tempfile
import unittest
from pathlib import Path

import check

HERE = Path(__file__).parent
FEATURES = {
    "default": [], "store": ["dep:rusqlite"], "fault-injection": ["store"],
    "runtime": ["store", "dep:tokio"], "transport": ["runtime", "tokio/net"], "full": ["transport"],
}


def meta(edges):
    """edges: (package, dependency, kind, features, local)."""
    names = sorted({e[0] for e in edges})
    pkgs = []
    for n in names:
        deps = [{"name": b, "kind": k, "features": f, "path": "/x" if local else None}
                for a, b, k, f, local in edges if a == n]
        pkgs.append({"name": n, "dependencies": deps, "manifest_path": f"/x/{n}/Cargo.toml"})
    return {"packages": pkgs}


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, src in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(src)
    return d


class ModuleRules(unittest.TestCase):
    def edges(self, files):
        return check.crate_edges(tree(files))

    def test_allowed_graph_passes(self):
        e = self.edges({
            "core/mod.rs": "use crate::protocol::Id;\nuse crate::{canonical, crypto::Digest};\n",
            "runtime/handlers/mod.rs": "use crate::store::Store;\n",
        })
        self.assertEqual(e, {("core", "protocol"), ("core", "canonical"), ("core", "crypto"),
                             ("runtime", "store")})
        self.assertEqual(check.module_violations(e, FEATURES), [])

    def test_upward_edge_through_grouped_import_fails(self):
        e = self.edges({"store/mod.rs": "use crate::{protocol::Id, runtime::{Runtime, X}};\n"})
        self.assertIn(("store", "runtime"), e)
        self.assertTrue(check.module_violations(e, FEATURES))

    def test_aliased_reexport_fails(self):
        e = self.edges({"core/mod.rs": "pub use crate::authority as auth;\n"})
        self.assertTrue(check.module_violations(e, FEATURES))

    def test_super_escape_fails(self):
        e = self.edges({"policy/eval.rs": "use super::super::execution::Lease;\n",
                        "policy/mod.rs": "mod eval;\n"})
        self.assertEqual(e, {("policy", "execution")})
        self.assertTrue(check.module_violations(e, FEATURES))

    def test_test_modules_are_exempt(self):
        e = self.edges({"core/mod.rs": "fn a() {}\n#[cfg(test)]\nmod t { use crate::runtime; }\n"})
        self.assertEqual(e, set())

    def test_cycle_detected(self):
        self.assertEqual(check.find_cycle({("a", "b"), ("b", "c"), ("c", "a")})[0],
                         check.find_cycle({("a", "b"), ("b", "c"), ("c", "a")})[-1])
        self.assertIsNone(check.find_cycle({("a", "b"), ("b", "c")}))
        self.assertTrue(check.module_violations({("crypto", "canonical"), ("canonical", "crypto")},
                                                FEATURES))

    def test_missing_feature_implication_fails(self):
        broken = dict(FEATURES, transport=["tokio/net"])
        self.assertTrue(check.module_violations({("transport", "runtime")}, broken))
        self.assertEqual(check.module_violations({("transport", "runtime")}, FEATURES), [])


class DependencyRules(unittest.TestCase):
    def test_allowed_graph_passes(self):
        m = meta([("openaevc", "serde", None, [], False),
                  ("openaevc", "proptest", "dev", [], False),
                  ("openaevc-testkit", "openaevc", None, ["runtime"], True),
                  ("openaevc-testkit", "openaevc", "dev", ["full", "fault-injection"], True),
                  ("openaevc-sdk", "openaevc", None, ["transport"], True),
                  ("openaevc-sdk", "openaevc-testkit", "dev", [], True),
                  ("openaevc-ext-reference-kv", "openaevc", None, [], True)])
        self.assertEqual(check.dependency_violations(m), [])

    def test_local_dependency_in_published_crate_fails(self):
        m = meta([("openaevc", "openaevc-testkit", "dev", [], True)])
        self.assertTrue(check.dependency_violations(m))

    def test_production_dep_on_testkit_fails(self):
        m = meta([("openaevcd", "openaevc-testkit", None, [], True)])
        self.assertTrue(check.dependency_violations(m))

    def test_production_fault_injection_fails(self):
        m = meta([("openaevcd", "openaevc", None, ["transport", "fault-injection"], True)])
        self.assertTrue(check.dependency_violations(m))

    def test_extension_enabling_runtime_fails(self):
        m = meta([("openaevc-ext-reference-kv", "openaevc", None, ["runtime"], True)])
        self.assertTrue(check.dependency_violations(m))

    def test_sdk_on_local_package_fails(self):
        m = meta([("openaevc-sdk", "openaevc-conformance", None, [], True)])
        self.assertTrue(check.dependency_violations(m))


class TextRules(unittest.TestCase):
    def test_vocabulary_and_markers_detected(self):
        self.assertTrue(check.text_violations("fn a() { /* open a pull request */ }", "x.rs"))
        self.assertTrue(check.text_violations("fn a() { t" + "odo!() }", "x.rs"))
        self.assertEqual(check.text_violations("fn a() {}", "x.rs"), [])

    def test_test_modules_are_exempt(self):
        src = "fn a() {}\n#[cfg(test)]\nmod tests { fn b() { un" + "implemented!() } }\n"
        self.assertEqual(check.text_violations(src, "x.rs"), [])

    def test_extension_source_on_runtime_fails(self):
        self.assertTrue(check.extension_source_violations("x.rs", "use openaevc::runtime::Runtime;"))
        self.assertEqual(check.extension_source_violations("x.rs", "use openaevc::extension::wire;"), [])


class Repository(unittest.TestCase):
    def test_repository_passes(self):
        self.assertEqual(check.main([]), 0)


class Coverage(unittest.TestCase):
    def test_unmapped_and_unknown_ids_fail(self):
        import coverage
        self.assertEqual(coverage.problems({"AEVC-A-0001"}, {"AEVC-A-0001"}), [])
        self.assertTrue(coverage.problems({"AEVC-A-0001", "AEVC-A-0002"}, {"AEVC-A-0001"}))
        self.assertTrue(coverage.problems({"AEVC-A-0001"}, {"AEVC-A-0001", "AEVC-B-0001"}))

    def test_repository_is_fully_covered(self):
        import coverage
        self.assertEqual(coverage.main(), 0)


if __name__ == "__main__":
    unittest.main()
