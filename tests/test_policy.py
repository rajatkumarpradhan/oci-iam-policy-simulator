import unittest

from oci_iam_policy_simulator.policy import evaluate, parse_policy

POLICY = """
# comment line
Allow group ops to manage instances in compartment prod
Allow group ops to read metrics in compartment prod where request.operation='GetMetricData'
Allow group auditors to read audit-events in tenancy
Allow group netops to use virtual-network-family in compartment prod/network
"""


class TestParse(unittest.TestCase):
    def test_parses_statements_and_skips_comments(self):
        statements, errors = parse_policy(POLICY)
        self.assertEqual(len(statements), 4)
        self.assertEqual(errors, [])
        self.assertEqual(statements[0].group, "ops")
        self.assertIsNone(statements[2].compartment)  # tenancy scope

    def test_unparseable_line_is_an_error(self):
        _, errors = parse_policy("Allow everyone everything")
        self.assertEqual(len(errors), 1)
        self.assertIn("line 1", errors[0])

    def test_where_clause_captured(self):
        statements, _ = parse_policy(POLICY)
        self.assertEqual(statements[1].where, "request.operation='GetMetricData'")


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.statements, _ = parse_policy(POLICY)

    def test_manage_covers_lower_verbs(self):
        allowed, matched = evaluate(self.statements, "ops", "read", "instances", "prod")
        self.assertTrue(allowed)
        self.assertEqual(matched.verb, "manage")

    def test_read_does_not_cover_manage(self):
        allowed, _ = evaluate(self.statements, "ops", "manage", "metrics", "prod")
        self.assertFalse(allowed)

    def test_subcompartment_inherits(self):
        allowed, _ = evaluate(self.statements, "netops", "use", "virtual-network-family", "prod/network/eu")
        self.assertTrue(allowed)

    def test_sibling_compartment_does_not_inherit(self):
        allowed, _ = evaluate(self.statements, "netops", "use", "virtual-network-family", "prod/storage")
        self.assertFalse(allowed)

    def test_tenancy_scope_matches_any_compartment(self):
        allowed, _ = evaluate(self.statements, "auditors", "read", "audit-events", "prod/finance")
        self.assertTrue(allowed)

    def test_operation_condition_match(self):
        allowed, _ = evaluate(self.statements, "ops", "read", "metrics", "prod", operation="GetMetricData")
        self.assertTrue(allowed)

    def test_operation_condition_mismatch_denies(self):
        allowed, _ = evaluate(self.statements, "ops", "read", "metrics", "prod", operation="ListMetrics")
        self.assertFalse(allowed)

    def test_unknown_condition_is_undecidable(self):
        statements, _ = parse_policy("Allow group x to read y in compartment c where request.time < '2027-01-01'")
        allowed, matched = evaluate(statements, "x", "read", "y", "c")
        self.assertIsNone(allowed)
        self.assertIsNotNone(matched)

    def test_all_resources_wildcard(self):
        statements, _ = parse_policy("Allow group admins to manage all-resources in tenancy")
        allowed, _ = evaluate(statements, "admins", "use", "buckets", "any-compartment")
        self.assertTrue(allowed)

    def test_wrong_group_denied(self):
        allowed, matched = evaluate(self.statements, "interns", "manage", "instances", "prod")
        self.assertFalse(allowed)
        self.assertIsNone(matched)


if __name__ == "__main__":
    unittest.main()
