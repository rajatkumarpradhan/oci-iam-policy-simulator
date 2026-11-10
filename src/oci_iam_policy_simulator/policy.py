"""Parse and evaluate simplified OCI IAM policy statements.

OCI IAM access is granted by policy statements like:
  Allow group ops-admins to manage instances in compartment prod
This module parses such statements and answers allow/deny questions for
synthetic requests. Verb hierarchy: inspect < read < use < manage.
'all-resources' matches any resource type; 'in tenancy' matches any
compartment; a compartment grant also covers its subcompartments
(path form 'a/b/c'). All offline; no OCI calls.
"""

import re
from dataclasses import dataclass

VERB_RANK = {"inspect": 1, "read": 2, "use": 3, "manage": 4}

STATEMENT_RE = re.compile(
    r"^allow\s+group\s+(?P<group>[\w.\- ]+?)\s+to\s+"
    r"(?P<verb>inspect|read|use|manage)\s+"
    r"(?P<resource>[\w\-]+)\s+in\s+"
    r"(?P<scope>compartment\s+(?P<compartment>[\w.\-/ ]+?)|tenancy)"
    r"(?:\s+where\s+(?P<where>.+))?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Statement:
    group: str
    verb: str
    resource: str
    compartment: str | None  # None means tenancy scope
    where: str | None
    line: int
    raw: str


def parse_policy(text):
    """Parse policy text into (statements, errors)."""
    statements, errors = [], []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = STATEMENT_RE.match(line)
        if not match:
            errors.append(f"line {lineno}: cannot parse statement: {line!r}")
            continue
        compartment = match.group("compartment")
        statements.append(
            Statement(
                group=match.group("group").strip().lower(),
                verb=match.group("verb").lower(),
                resource=match.group("resource").lower(),
                compartment=compartment.strip().lower() if compartment else None,
                where=(match.group("where") or "").strip() or None,
                line=lineno,
                raw=line,
            )
        )
    return statements, errors


def _scope_matches(statement, compartment):
    if statement.compartment is None:
        return True
    comp = compartment.strip().lower()
    granted = statement.compartment
    return comp == granted or comp.startswith(granted + "/")


def _where_matches(statement, operation):
    """Only request.operation='X' equality conditions are evaluated."""
    if statement.where is None:
        return True
    m = re.fullmatch(r"request\.operation\s*=\s*'([^']+)'", statement.where)
    if m:
        return operation == m.group(1)
    return None  # unknown condition: cannot decide


def evaluate(statements, group, verb, resource, compartment, operation=None):
    """Return (allowed, matched_statement_or_None).

    allowed is True/False, or None when every candidate statement has a
    condition we cannot evaluate.
    """
    group = group.strip().lower()
    for statement in statements:
        if statement.group != group:
            continue
        if VERB_RANK[statement.verb] < VERB_RANK[verb.lower()]:
            continue
        if statement.resource != "all-resources" and statement.resource != resource.lower():
            continue
        if not _scope_matches(statement, compartment):
            continue
        verdict = _where_matches(statement, operation)
        if verdict is True:
            return True, statement
        if verdict is None:
            return None, statement
    return False, None
