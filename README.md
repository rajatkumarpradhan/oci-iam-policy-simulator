# oci-iam-policy-simulator

**Custom portfolio tool (no built-in OCI services wired in).** Offline simulator for simplified OCI IAM policy statements. Paste a policy file, get allow/deny answers for synthetic access queries plus findings that flag risky grants - before anything is ever applied in a tenancy.

Problem it solves: "would this group actually get (or lose) access if I wrote this policy?" answered locally, in CI, without a tenancy.

## What it is

A parser + evaluator for OCI-style `Allow group <name> to <verb> <resource-type> in compartment <name>` statements, with the real IAM semantics that matter most:

- Verb hierarchy: `inspect < read < use < manage` (manage covers lower verbs).
- `all-resources` matches any resource type; `in tenancy` matches any compartment.
- Compartment grants cover subcompartments (`prod` covers `prod/network/eu`, not `prod` siblings).
- `where request.operation='X'` conditions are evaluated; other conditions are reported as undecidable rather than guessed.

On top of evaluation, four rules flag hygiene problems in the policy itself.

- Runs 100% locally. No OCI SDK, no credentials, no network calls.
- 25 unit tests, all executed locally and in CI on Python 3.10/3.11/3.12.
- Exit code 2 on HIGH findings; 1 on unreadable/unparseable input; 0 otherwise.

## What it is NOT (honest limits)

- The statement grammar is a **simplified subset** of OCI IAM policy: no dynamic groups, no `any-user`, no resource principals, no multiple groups per statement, no tag-based conditions.
- Only `where request.operation='X'` equality conditions are evaluated; every other condition yields "cannot decide" (LOW finding), never a guessed verdict.
- This is a simulator, not the OCI IAM decision engine. Real evaluation involves group membership, tag context and service-side rules this tool does not model.
- Denied queries are reported as findings (SIM001 MEDIUM) on the assumption that a query you wrote down is access you expected to work.

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| SIM001 | MEDIUM/LOW | Access query denied (or conditional/undecidable) |
| SIM002 | HIGH | `manage all-resources` grant; extremely broad |
| SIM003 | LOW | Exact duplicate statement |
| SIM004 | LOW | Conditional statement; only request.operation equality is simulated |

## Run

Requires Python 3.10+, no third-party dependencies.

```sh
PYTHONPATH=src python3 -m oci_iam_policy_simulator samples/risky-policy.txt --queries samples/risky-queries.json
PYTHONPATH=src python3 -m oci_iam_policy_simulator samples/tidy-policy.txt --queries samples/tidy-queries.json
```

Or the end-to-end demo:

```sh
sh demo.sh
```

Expected demo output: the risky policy flags the `manage all-resources in tenancy` grant (HIGH), the denied audit-team query, a duplicate statement and a conditional statement, and exits 2; the tidy least-privilege policy reports zero findings and exits 0.

## Test

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
