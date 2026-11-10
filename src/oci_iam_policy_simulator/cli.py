"""Command line interface for the IAM policy simulator."""

import argparse
import json
import sys

from .analyze import SEVERITY_ORDER, analyze
from .policy import evaluate, parse_policy

EXIT_HIGH_FINDINGS = 2
EXIT_INPUT_ERROR = 1
EXIT_OK = 0


def _load_text(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def _load_queries(path):
    if path is None:
        return []
    try:
        data = json.loads(_load_text(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError(f"{path} must contain a JSON list of queries")
    for query in data:
        for field in ("group", "verb", "resource", "compartment"):
            if field not in query:
                raise ValueError(f"query missing required field {field!r}: {query}")
    return data


def _render(findings, n_statements, n_queries):
    lines = []
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
        lines.append(f"[{finding.severity:<6}] {finding.rule_id} {finding.subject}: {finding.message}")
    lines.append(
        "summary: {high} high, {medium} medium, {low} low finding(s); {s} statement(s), {q} query(ies)".format(
            high=counts["HIGH"], medium=counts["MEDIUM"], low=counts["LOW"], s=n_statements, q=n_queries
        )
    )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="oci-iam-policy-simulator",
        description="Offline OCI IAM policy simulator: parse statements, answer access queries, flag risky grants.",
    )
    parser.add_argument("policy", help="policy file, one Allow statement per line")
    parser.add_argument("--queries", help="optional JSON list of access queries")
    args = parser.parse_args(argv)

    try:
        statements, errors = parse_policy(_load_text(args.policy))
        queries = _load_queries(args.queries)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        return EXIT_INPUT_ERROR

    findings = analyze(statements, queries)
    print(_render(findings, len(statements), len(queries)))
    if any(f.severity == "HIGH" for f in findings):
        return EXIT_HIGH_FINDINGS
    return EXIT_OK
