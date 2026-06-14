# Enterprise Scale: AWS Organizations Mode

This document is a design, not a shipped feature. It describes how the engine
extends from scanning a single AWS account to governing non-human identities
across an entire AWS Organization, and why the current architecture already
supports that extension cleanly.

## Why this is a small change, not a rewrite

The engine is built as `Collector -> Detectors -> Reporter`, where a collector
produces a list of identity records and everything downstream operates on those
records. The detectors are pure functions over a record, and the reporters
consume the assembled report. Nothing downstream of collection knows or cares
which account a record came from.

That boundary is the whole point. Multi-account support is a new collector that
yields records from many accounts, tagged with their source account. The eleven
detectors, the scoring, the exception register, and the JSON and Markdown
reporters are reused unchanged.

## Current state

One `AwsCollector` reads one account over read-only boto3 calls. Its credentials
come from the Phase 2 GitHub OIDC role in a single account. The threat model
bounds a worst-case compromise to read-only reconnaissance in that one account.

## Target architecture

A hub-and-spoke model. A central security-tooling account runs the scanner and
assumes a read-only role in each member account to collect identities. Findings
are aggregated and stored centrally.

```
                    GitHub Actions (OIDC, no stored keys)
                                  |
                                  v
                 Security Tooling Account (the hub)
                 - github-actions-nhi-scan        (OIDC entry, Phase 2)
                 - OrganizationsCollector          (lists accounts, assumes in)
                                  |
            sts:AssumeRole (read-only, short-lived) into each member
              |                   |                   |
              v                   v                   v
        Member Account A    Member Account B    Member Account C
        nhi-scan-readonly   nhi-scan-readonly   nhi-scan-readonly
        (read-only role, trusts the org, not a bare account principal)
              |                   |                   |
              +---------+---------+-------------------+
                        v
            Central evidence (S3) -> org rollup report -> dashboard
```

## Identity and trust model

The federation entry point is unchanged: GitHub Actions assumes the central
`github-actions-nhi-scan` role via OIDC, with no stored AWS keys. What is new is
the spoke role.

Each member account holds a read-only `nhi-scan-readonly` role whose permissions
are exactly the engine's existing least-privilege policy, the same set
`--print-policy` emits today. Its trust policy allows only the central scanner
principal to assume it, scoped with an `aws:PrincipalOrgID` condition so that
only a principal inside this Organization can assume it even if the role ARN
leaks.

This is a deliberate design choice and an instance of the engine's own dogfooding
discipline. The engine's cross-account trust detector flags external-account
trust that lacks an `sts:ExternalId`, but for internal Organization
account-to-account access the correct control is not ExternalId (which is for
third-party access); it is an `aws:PrincipalOrgID` or Organization-account
condition. The spoke roles use that control, so the scanner does not create the
confused-deputy pattern it is built to find. This is also the context the
cross-account detector should learn to distinguish: internal Org trust with an
Org condition is acceptable, third-party trust without ExternalId is not.

The central scanner's own permissions grow by exactly two things beyond the
existing read-only set: `organizations:ListAccounts` and `DescribeAccount` to
enumerate the estate, and `sts:AssumeRole` limited to the `nhi-scan-readonly`
role path across the Organization.

## Account discovery

The collector enumerates member accounts with the AWS Organizations API, run
from the management account or, preferably, a delegated administrator account so
the hub is not the management account itself. Discovery can be filtered to
specific Organizational Units, so a scan can target, for example, only the
production OU.

## Collection at scale

`OrganizationsCollector` lists the in-scope accounts, and for each one assumes
that account's `nhi-scan-readonly` role for a short-lived session, instantiates
the existing `AwsCollector` with those credentials, collects its records, and
tags each record with the source account id. The per-account scans are
independent, so they parallelize cleanly across a thread or process pool, which
is what keeps a hundred-account scan to roughly the wall-clock time of one.

The detectors then run over the combined, account-tagged record set with no
changes, because a record is a record regardless of which account produced it.

## Aggregation, evidence, and reporting

Findings carry their account id, so the central reporter can produce both
per-account reports and an Organization rollup: net residual risk by account, by
severity, and by OWASP NHI category. Reports are written to a central evidence
bucket in the security-tooling account, which is the system of record an auditor
can point to.

The exception register becomes Organization-wide. Because every finding id is
already namespaced by its identity, a central register can accept a finding in a
specific account without ambiguity, and the net-residual rollup reflects those
acceptances across the whole estate. The same CI gate logic applies at the
Organization level: fail when any account carries an open HIGH or CRITICAL.

A dashboard is the final, optional layer over the evidence bucket: trend of net
residual risk over time, worst accounts, and most common finding types. The
engine produces the evidence; the dashboard only visualizes it.

## Deployment and coverage

The `nhi-scan-readonly` role is deployed to every account with CloudFormation
StackSets in service-managed mode with automatic deployment, so that new accounts
joining the Organization receive the role automatically and coverage never
silently lapses. Consistent, automatic role deployment is itself a governance
control: it means the scanner cannot be quietly excluded from an account.

## Security at scale

This is where the threat model has to extend honestly. A hub that can assume a
read-only role in every account has real reach, and that reach is the asset to
protect. The mitigations are the same ones the single-account design already
relies on, now load-bearing across the estate:

- Every spoke role is read-only, the exact `--print-policy` set, with no write,
  delete, or policy-modifying actions anywhere.
- Spoke trust is scoped by `aws:PrincipalOrgID` and to the single central
  scanner principal, so a leaked role ARN is not assumable from outside the org.
- Sessions are short-lived assumed-role credentials, not static keys.
- The hub holds no standing write access to any member account.

So the worst credible outcome of a hub compromise remains disclosure of identity
and secret-metadata posture across the Organization for a session window, which
is reconnaissance, not modification or destruction. The read-only constraint is
what makes scanning the entire estate a defensible thing to do rather than a
concentration of risk.

## Rollout, in order

1. Deploy `nhi-scan-readonly` to all accounts via service-managed StackSets.
2. Add `OrganizationsCollector` (list accounts, assume per account, collect,
   tag by account). Detectors and reporters are untouched.
3. Add the central evidence bucket and the Organization rollup report.
4. Add the dashboard over the evidence bucket.

Each step is independently shippable, and the engine keeps working as a
single-account tool throughout, since `OrganizationsCollector` is an addition
alongside `AwsCollector`, not a replacement for it.
