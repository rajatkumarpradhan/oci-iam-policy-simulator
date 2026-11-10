import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from oci_iam_policy_simulator.analyze import analyze
from oci_iam_policy_simulator.cli import main
from oci_iam_policy_simulator.policy import parse_policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ids(findings):
    return {f.rule_id for f in findings}


class TestAnalyze(unittest.TestCase):
    def test_sim002_broad_grant(self):
        statements, _ = parse_policy("Allow group a to manage all-resources in tenancy")
        self.assertIn("SIM002", ids(analyze(statements, [])))
        self.assertEqual(analyze(statements, [])[0].severity, "HIGH")

    def test_sim002_not_for_scoped_manage(self):
        statements, _ = parse_policy("Allow group a to manage instances in compartment prod")
        self.assertNotIn("SIM002", ids(analyze(statements, [])))

    def test_sim003_duplicate(self):
        statements, _ = parse_policy(
            "Allow group a to read x in compartment c\nAllow group a to read x in compartment c"
        )
        self.assertIn("SIM003", ids(analyze(statements, [])))

    def test_sim004_conditional(self):
        statements, _ = parse_policy("Allow group a to read x in compartment c where request.operation='Get'")
        self.assertIn("SIM004", ids(analyze(statements, [])))

    def test_sim001_denied_query(self):
        statements, _ = parse_policy("Allow group a to read x in compartment c")
        findings = analyze(statements, [{"group": "b", "verb": "read", "resource": "x", "compartment": "c"}])
        self.assertIn("SIM001", ids(findings))
        self.assertEqual([f for f in findings if f.rule_id == "SIM001"][0].severity, "MEDIUM")

    def test_granted_query_no_finding(self):
        statements, _ = parse_policy("Allow group a to read x in compartment c")
        self.assertEqual(analyze(statements, [{"group": "a", "verb": "read", "resource": "x", "compartment": "c"}]), [])

    def test_findings_sorted_high_first(self):
        statements, _ = parse_policy(
            "Allow group a to manage all-resources in tenancy\nAllow group a to read x in compartment c"
        )
        findings = analyze(statements, [{"group": "b", "verb": "read", "resource": "x", "compartment": "c"}])
        self.assertEqual(findings[0].severity, "HIGH")


class TestCli(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_missing_file_exits_1(self):
        code, _, _ = self._run(["/nonexistent/policy.txt"])
        self.assertEqual(code, 1)

    def test_risky_sample_exits_2(self):
        code, out, _ = self._run([
            os.path.join(ROOT, "samples", "risky-policy.txt"),
            "--queries", os.path.join(ROOT, "samples", "risky-queries.json"),
        ])
        self.assertEqual(code, 2)
        self.assertIn("SIM002", out)
        self.assertIn("SIM001", out)
        self.assertIn("summary:", out)

    def test_tidy_sample_exits_0(self):
        code, out, _ = self._run([
            os.path.join(ROOT, "samples", "tidy-policy.txt"),
            "--queries", os.path.join(ROOT, "samples", "tidy-queries.json"),
        ])
        self.assertEqual(code, 0)
        self.assertIn("0 high", out)

    def test_unparseable_policy_exits_1(self):
        bad = os.path.join(ROOT, "samples", "risky-queries.json")
        code, _, err = self._run([bad])
        self.assertEqual(code, 1)
        self.assertIn("cannot parse", err)

    def test_query_missing_field_exits_1(self):
        path = os.path.join(ROOT, "tests", "bad-queries.json")
        with open(path, "w") as fh:
            fh.write('[{"group": "a"}]')
        try:
            code, _, err = self._run([
                os.path.join(ROOT, "samples", "tidy-policy.txt"), "--queries", path])
            self.assertEqual(code, 1)
            self.assertIn("missing required field", err)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
