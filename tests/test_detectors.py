"""Unit tests for the NHI governance engine detectors.

Detectors are pure functions over an NHIRecord, so they test with no AWS
credentials and no network. Each test asserts the security logic itself: the
right finding fires for a misconfigured identity, and a healthy identity
produces nothing. In GRC terms, these are the tests for the control tests.

Run from the repo root:
    pip install pytest
    python -m pytest -q
"""

#
from nhi_governance_engine import (
    NHIRecord, NHIType, AccessKey, Config, Severity, CredentialModel,
    classify_credential_model,
    detect_missing_owner,
    detect_orphaned_role,
    detect_stale_access_key,
    detect_static_credential_model,
    detect_wildcard_policy,
    detect_permissive_trust_policy,
    detect_cross_account_without_externalid,
    detect_federated_trust_gaps,
    detect_overprivileged_managed_policy,
    detect_unused_permissions,
    detect_secret_no_rotation,
    run_detectors,
)

CFG = Config()


def fire(detector, rec, cfg=CFG):
    """Run one detector and return its findings as a list."""
    return list(detector(rec, cfg))


# --- missing owner ---------------------------------------------------------

def test_missing_owner_flagged_when_no_owner_tag():
    rec = NHIRecord(id="arn:role/x", name="x", nhi_type=NHIType.IAM_ROLE, tags={})
    out = fire(detect_missing_owner, rec)
    assert len(out) == 1
    assert out[0].finding_id == "NHI-NO-OWNER:x"
    assert out[0].severity == Severity.MEDIUM


def test_missing_owner_not_flagged_when_owner_present():
    rec = NHIRecord(id="arn:role/x", name="x", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "platform@example.com"})
    assert fire(detect_missing_owner, rec) == []


# --- orphaned / stale role -------------------------------------------------

def test_role_never_used_flagged():
    rec = NHIRecord(id="arn:role/old", name="old", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"}, created_days_ago=200, last_used_days=None)
    out = fire(detect_orphaned_role, rec)
    assert len(out) == 1
    assert out[0].finding_id == "NHI-ROLE-NEVER-USED:old"


def test_role_stale_flagged():
    rec = NHIRecord(id="arn:role/stale", name="stale", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"}, last_used_days=120)
    out = fire(detect_orphaned_role, rec)
    assert len(out) == 1
    assert out[0].finding_id == "NHI-ROLE-STALE:stale"


def test_recently_used_role_not_flagged():
    rec = NHIRecord(id="arn:role/active", name="active", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"}, last_used_days=3)
    assert fire(detect_orphaned_role, rec) == []


# --- stale access key ------------------------------------------------------

def test_old_active_key_flagged_high():
    rec = NHIRecord(id="arn:user/u", name="u", nhi_type=NHIType.IAM_USER,
                    tags={"Owner": "team"},
                    access_keys=[AccessKey(key_id="AKIA0000000000001234",
                                           age_days=420, last_used_days=10,
                                           status="Active")])
    out = fire(detect_stale_access_key, rec)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_fresh_key_not_flagged():
    rec = NHIRecord(id="arn:user/u", name="u", nhi_type=NHIType.IAM_USER,
                    tags={"Owner": "team"},
                    access_keys=[AccessKey(key_id="AKIA0000000000001234",
                                           age_days=10, last_used_days=1,
                                           status="Active")])
    assert fire(detect_stale_access_key, rec) == []


def test_inactive_old_key_not_flagged():
    rec = NHIRecord(id="arn:user/u", name="u", nhi_type=NHIType.IAM_USER,
                    tags={"Owner": "team"},
                    access_keys=[AccessKey(key_id="AKIA0000000000001234",
                                           age_days=999, last_used_days=None,
                                           status="Inactive")])
    assert fire(detect_stale_access_key, rec) == []


# --- static credential model ----------------------------------------------

def test_static_credential_model_flagged():
    rec = NHIRecord(id="arn:user/u", name="u", nhi_type=NHIType.IAM_USER,
                    tags={"Owner": "team"},
                    access_keys=[AccessKey("AKIA0000000000001234", 10, 1, "Active")],
                    credential_model=CredentialModel.STATIC_LONG_LIVED)
    out = fire(detect_static_credential_model, rec)
    assert len(out) == 1
    assert out[0].owasp_nhi.startswith("NHI4:2025")


# --- wildcard admin policy -------------------------------------------------

def test_wildcard_admin_policy_flagged_high():
    rec = NHIRecord(id="arn:role/admin", name="admin", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    policy_statements=[{"Effect": "Allow", "Action": "*",
                                        "Resource": "*"}])
    out = fire(detect_wildcard_policy, rec)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_scoped_policy_not_flagged():
    rec = NHIRecord(id="arn:role/scoped", name="scoped", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    policy_statements=[{"Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": ["arn:aws:s3:::bucket/*"]}])
    assert fire(detect_wildcard_policy, rec) == []


# --- permissive trust policy ----------------------------------------------

def test_wildcard_trust_policy_flagged_critical():
    rec = NHIRecord(id="arn:role/etl", name="etl", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    trust_policy={"Statement": [{"Effect": "Allow",
                                                 "Principal": {"AWS": "*"},
                                                 "Action": "sts:AssumeRole"}]})
    out = fire(detect_permissive_trust_policy, rec)
    assert len(out) == 1
    assert out[0].severity == Severity.CRITICAL


def test_scoped_trust_policy_not_flagged():
    rec = NHIRecord(id="arn:role/etl", name="etl", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    trust_policy={"Statement": [{"Effect": "Allow",
                                                 "Principal": {"AWS":
                                                    "arn:aws:iam::111122223333:root"},
                                                 "Action": "sts:AssumeRole"}]})
    assert fire(detect_permissive_trust_policy, rec) == []


# --- secret rotation -------------------------------------------------------

def test_secret_rotation_disabled_flagged():
    rec = NHIRecord(id="arn:secret/db", name="db", nhi_type=NHIType.SECRET,
                    tags={"Owner": "team"}, rotation_enabled=False)
    assert len(fire(detect_secret_no_rotation, rec)) == 1


def test_secret_rotation_enabled_not_flagged():
    rec = NHIRecord(id="arn:secret/db", name="db", nhi_type=NHIType.SECRET,
                    tags={"Owner": "team"}, rotation_enabled=True)
    assert fire(detect_secret_no_rotation, rec) == []


# --- credential-model classification ---------------------------------------

def test_classify_oidc_role_as_federated():
    rec = NHIRecord(id="arn:role/gh", name="gh", nhi_type=NHIType.IAM_ROLE,
                    trust_policy={"Statement": [{"Principal": {"Federated":
                        "arn:aws:iam::111:oidc-provider/token.actions.githubusercontent.com"}}]})
    assert classify_credential_model(rec) == CredentialModel.FEDERATED_OIDC


def test_classify_user_with_keys_as_static():
    rec = NHIRecord(id="arn:user/u", name="u", nhi_type=NHIType.IAM_USER,
                    access_keys=[AccessKey("AKIA0000000000001234", 5, 1, "Active")])
    assert classify_credential_model(rec) == CredentialModel.STATIC_LONG_LIVED


# --- healthy identity: zero findings across all detectors ------------------

def test_healthy_role_produces_no_findings():
    rec = NHIRecord(
        id="arn:role/healthy", name="healthy", nhi_type=NHIType.IAM_ROLE,
        tags={"Owner": "platform@example.com"},
        last_used_days=2,
        trust_policy={"Statement": [{"Effect": "Allow",
                                     "Principal": {"Service": "lambda.amazonaws.com"},
                                     "Action": "sts:AssumeRole"}]},
        policy_statements=[{"Effect": "Allow", "Action": ["dynamodb:GetItem"],
                            "Resource": ["arn:aws:dynamodb:*:*:table/app"]}],
        credential_model=CredentialModel.STS_ASSUMED,
    )
    assert run_detectors([rec], CFG) == []

# --- overprivileged managed policy ----------------------------------------

def test_admin_managed_policy_flagged_by_arn():
    rec = NHIRecord(id="arn:role/app", name="app", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    attached_managed_policies=[{
                        "name": "AdministratorAccess",
                        "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "aws_managed": True, "statements": []}])
    out = fire(detect_overprivileged_managed_policy, rec)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH
    assert out[0].owasp_nhi.startswith("NHI5:2025")


def test_wildcard_customer_managed_policy_flagged():
    rec = NHIRecord(id="arn:role/app", name="app", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    attached_managed_policies=[{
                        "name": "team-power", "arn": "arn:aws:iam::111:policy/team-power",
                        "aws_managed": False,
                        "statements": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}])
    assert len(fire(detect_overprivileged_managed_policy, rec)) == 1


def test_scoped_managed_policy_not_flagged():
    rec = NHIRecord(id="arn:role/app", name="app", nhi_type=NHIType.IAM_ROLE,
                    tags={"Owner": "team"},
                    attached_managed_policies=[{
                        "name": "s3-read", "arn": "arn:aws:iam::111:policy/s3-read",
                        "aws_managed": False,
                        "statements": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                                        "Resource": "arn:aws:s3:::b/*"}]}])
    assert fire(detect_overprivileged_managed_policy, rec) == []


# --- cross-account trust without ExternalId --------------------------------

def _role(trust):
    return NHIRecord(id="arn:aws:iam::000000000000:role/r", name="r",
                     nhi_type=NHIType.IAM_ROLE, tags={"Owner": "t"},
                     trust_policy=trust)

def test_cross_account_without_externalid_flagged():
    rec = _role({"Statement": [{"Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Action": "sts:AssumeRole"}]})
    out = fire(detect_cross_account_without_externalid, rec)
    assert len(out) == 1 and out[0].severity == Severity.HIGH

def test_cross_account_with_externalid_not_flagged():
    rec = _role({"Statement": [{"Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                 "Action": "sts:AssumeRole",
                 "Condition": {"StringEquals": {"sts:ExternalId": "shared-secret"}}}]})
    assert fire(detect_cross_account_without_externalid, rec) == []

def test_same_account_trust_not_flagged():
    rec = _role({"Statement": [{"Effect": "Allow",
                 "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                 "Action": "sts:AssumeRole"}]})
    assert fire(detect_cross_account_without_externalid, rec) == []


# --- federated (OIDC) trust gaps -------------------------------------------

def _gh(condition):
    return _role({"Statement": [{"Effect": "Allow",
                  "Principal": {"Federated":
                      "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
                  "Action": "sts:AssumeRoleWithWebIdentity",
                  "Condition": condition}]})

def test_oidc_missing_aud_flagged():
    rec = _gh({"StringLike": {"token.actions.githubusercontent.com:sub":
                              "repo:uzobola/aws-nhi-governance-engine:ref:refs/heads/main"}})
    ids = {f.finding_id.split(":")[0] for f in fire(detect_federated_trust_gaps, rec)}
    assert "NHI-OIDC-NO-AUD" in ids

def test_oidc_missing_sub_flagged():
    rec = _gh({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})
    ids = {f.finding_id.split(":")[0] for f in fire(detect_federated_trust_gaps, rec)}
    assert "NHI-OIDC-NO-SUB" in ids

def test_github_oidc_unscoped_sub_flagged():
    rec = _gh({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
               "StringLike": {"token.actions.githubusercontent.com:sub": "*"}})
    ids = {f.finding_id.split(":")[0] for f in fire(detect_federated_trust_gaps, rec)}
    assert ids == {"NHI-GH-OIDC-UNSCOPED"}

def test_github_oidc_scoped_sub_clean():
    rec = _gh({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
               "StringLike": {"token.actions.githubusercontent.com:sub":
                              "repo:uzobola/aws-nhi-governance-engine:ref:refs/heads/main"}})
    assert fire(detect_federated_trust_gaps, rec) == []


# --- unused permissions (Access Advisor) -----------------------------------

def _role_sla(sla):
    return NHIRecord(id="arn:aws:iam::000000000000:role/r", name="r",
                     nhi_type=NHIType.IAM_ROLE, tags={"Owner": "t"},
                     service_last_accessed=sla)

def test_unused_permissions_flagged_for_never_and_stale():
    rec = _role_sla([{"service": "s3", "last_authenticated_days": 3},
                     {"service": "ec2", "last_authenticated_days": None},
                     {"service": "iam", "last_authenticated_days": 400}])
    out = fire(detect_unused_permissions, rec)
    assert len(out) == 1 and out[0].severity == Severity.MEDIUM
    assert out[0].evidence["unused_services"] == ["ec2", "iam"]

def test_unused_permissions_clean_when_all_recent():
    rec = _role_sla([{"service": "s3", "last_authenticated_days": 3},
                     {"service": "dynamodb", "last_authenticated_days": 10}])
    assert fire(detect_unused_permissions, rec) == []

def test_unused_permissions_skips_when_no_access_advisor_data():
    rec = _role_sla([])
    assert fire(detect_unused_permissions, rec) == []


# --- markdown reporter -----------------------------------------------------

from nhi_governance_engine.reporting import render_markdown

def _report(findings):
    return {"generated_at": "2026-01-01T00:00:00Z", "account_id": "123456789012",
            "scope": "test-scope",
            "summary": {"nhi_total": 1,
                        "nhi_by_type": {"iam_role": 1, "iam_user": 0, "secret": 0},
                        "findings_total": len(findings),
                        "findings_by_severity": {"INFO": 0, "LOW": 0, "MEDIUM": 0,
                                                 "HIGH": len(findings), "CRITICAL": 0}},
            "findings": findings}

def test_markdown_renders_core_sections():
    md = render_markdown(_report([{
        "finding_id": "NHI-X:r", "nhi_id": "arn:aws:iam::123:role/r",
        "nhi_type": "iam_role", "title": "Test finding", "severity": "HIGH",
        "owasp_nhi": "NHI5:2025 Overprivileged NHI", "nist_800_53": "AC-6",
        "evidence": {"unused_services": ["s3", "ec2"]}, "remediation": "Do the thing."}]))
    assert "# NHI Governance Report" in md
    assert "123456789012" in md
    assert "### HIGH (1)" in md
    assert "Test finding" in md
    assert "s3, ec2" in md
    assert "Do the thing." in md

def test_markdown_handles_no_findings():
    md = render_markdown(_report([]))
    assert "No open findings" in md


# --- exception register ----------------------------------------------------

from datetime import date
from nhi_governance_engine.exceptions import is_active, match_exception
from nhi_governance_engine.reporting import build_report
from nhi_governance_engine.models import Finding

def test_exception_active_and_expiry():
    assert is_active({}, date(2026, 1, 1)) is True
    assert is_active({"expires": "2026-12-31"}, date(2026, 6, 1)) is True
    assert is_active({"expires": "2026-01-01"}, date(2026, 6, 1)) is False

def test_match_exception_by_finding_id():
    exc = [{"finding_id": "NHI-X:r", "reason": "ok", "owner": "o"}]
    assert match_exception("NHI-X:r", exc, date(2026, 1, 1)) is not None
    assert match_exception("NHI-Y:r", exc, date(2026, 1, 1)) is None

def test_build_report_marks_accepted_and_excludes_from_net_residual():
    findings = [Finding(finding_id="NHI-A:r", nhi_id="arn:aws:iam::1:role/r",
                        nhi_type="iam_role", title="t", severity=Severity.HIGH,
                        owasp_nhi="NHI5:2025 x", nist_800_53="AC-6",
                        evidence={}, remediation="fix")]
    recs = [NHIRecord(id="arn:aws:iam::1:role/r", name="r", nhi_type=NHIType.IAM_ROLE)]
    rep = build_report(recs, findings, "123",
                       [{"finding_id": "NHI-A:r", "reason": "accepted", "owner": "o"}])
    assert rep["summary"]["findings_accepted"] == 1
    assert rep["summary"]["findings_open"] == 0
    assert rep["summary"]["net_residual_by_severity"]["HIGH"] == 0
    assert rep["summary"]["findings_by_severity"]["HIGH"] == 1   # total still counts it
    assert rep["findings"][0]["status"] == "accepted"
    assert rep["findings"][0]["exception"]["reason"] == "accepted"

def test_build_report_open_when_no_matching_exception():
    findings = [Finding(finding_id="NHI-A:r", nhi_id="arn:aws:iam::1:role/r",
                        nhi_type="iam_role", title="t", severity=Severity.HIGH,
                        owasp_nhi="NHI5:2025 x", nist_800_53="AC-6",
                        evidence={}, remediation="fix")]
    recs = [NHIRecord(id="arn:aws:iam::1:role/r", name="r", nhi_type=NHIType.IAM_ROLE)]
    rep = build_report(recs, findings, "123", [])
    assert rep["summary"]["findings_open"] == 1
    assert rep["summary"]["net_residual_by_severity"]["HIGH"] == 1
    assert rep["findings"][0]["status"] == "open"
