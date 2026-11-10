#!/bin/sh
# Simulates the risky policy (over-broad grant + denied audit query -> exit 2),
# then the tidy policy (all queries granted, no broad grants -> exit 0).
set -u
export PYTHONPATH="$(dirname "$0")/src"

echo "=== Simulating samples/risky-policy.txt ==="
python3 -m oci_iam_policy_simulator samples/risky-policy.txt --queries samples/risky-queries.json
echo "exit code: $? (2 = high-severity grant finding, expected for the risky set)"
echo
echo "=== Simulating samples/tidy-policy.txt ==="
python3 -m oci_iam_policy_simulator samples/tidy-policy.txt --queries samples/tidy-queries.json
echo "exit code: $? (0 = no high-severity findings, expected for the tidy set)"
