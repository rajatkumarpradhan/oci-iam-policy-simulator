"""Rule checks over parsed statements and synthetic access queries."""

from dataclasses import dataclass

from .policy import evaluate

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    subject: str
    message: str


def run_query_checks(statements, queries):
    findings = []
    for query in queries:
        label = f"{query['group']} -> {query['verb']} {query['resource']} in {query['compartment']}"
        allowed, matched = evaluate(
            statements,
            query["group"],
            query["verb"],
            query["resource"],
            query["compartment"],
            query.get("operation"),
        )
        if allowed is False:
            findings.append(Finding("SIM001", "MEDIUM", label, "access DENIED; no statement grants this"))
        elif allowed is None:
            findings.append(Finding("SIM001", "LOW", label,
                                    "cannot decide; the only granting statement has a condition this simulator does not evaluate"))
        elif matched and matched.where:
            findings.append(Finding("SIM001", "LOW", label, f"allowed conditionally (line {matched.line})"))
    return findings


def run_statement_checks(statements):
    findings = []
    seen = {}
    for s in statements:
        if s.resource == "all-resources" and s.verb == "manage":
            findings.append(Finding("SIM002", "HIGH", f"line {s.line}",
                                    f"'manage all-resources' granted to group '{s.group}' ({s.compartment or 'tenancy'} scope); extremely broad"))
        key = (s.group, s.verb, s.resource, s.compartment, s.where)
        if key in seen:
            findings.append(Finding("SIM003", "LOW", f"line {s.line}", f"duplicates line {seen[key]}"))
        else:
            seen[key] = s.line
        if s.where:
            findings.append(Finding("SIM004", "LOW", f"line {s.line}",
                                    f"conditional statement: {s.where}; only request.operation equality is simulated"))
    return findings


def analyze(statements, queries):
    findings = run_statement_checks(statements) + run_query_checks(statements, queries)
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.subject))
