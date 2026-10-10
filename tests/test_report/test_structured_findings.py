"""Construct extraction and cross-run fingerprints for the three skills
whose findings are persisted (sast / sca-reachability / secret-scanning)."""

from __future__ import annotations

from secfoo.report import sca, secret_scanning
from secfoo.report.sast import extract_construct_by_id
from secfoo.report.sast import findings_with_fingerprints as sast_findings

SAST_REPORT = """\
# SAST Report

## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | SQL Injection via raw query | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:42` | Confirmed |
| F2 | Old-style finding | Low | CWE-327 | unverified | AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N | `app/crypto.py:3` | Latent |

## 4. Detailed Findings

### [HIGH] F1: SQL Injection via raw query
- **Location:** `app/db.py:42`
- **Description:** Search term concatenated into SQL.
- **Construct:** SQL query built by string formatting with a request parameter, passed to a raw cursor execute
- **Recommendation:** Use parameterized queries.

### [LOW] F2: Old-style finding
- **Description:** Predates the Construct field.
- **Recommendation:** n/a
"""

SCA_REPORT = """\
# SCA Report

## 2. Dependency Inventory
| Package | Version | Direct/Transitive | Ecosystem | Source manifest |
|---------|---------|--------------------|-----------|------------------|
| PyYAML | 5.3 | Direct | PyPI | requirements.txt |
| lodash | 4.17.15 | Transitive | npm | package-lock.json |

## 4. Risk Register
| ID | Package | Version | Issue | Severity | Reachability | Fixed in |
|----|---------|---------|-------|----------|--------------|----------|
| D1 | PyYAML | 5.3 | Unsafe load of untrusted YAML | High | Reachable | 5.4 |
| D2 | lodash | 4.17.15 | Prototype pollution in merge | Medium | Conditionally reachable | 4.17.21 |
| D3 | lodash | 4.17.15 | ReDoS in trim | Low | Not reachable | 4.17.21 |

## 5. Detailed Findings

### [HIGH] D1: PyYAML@5.3 — unsafe load
- **Package / version:** PyYAML 5.3, **CVE:** CVE-2020-14343, **Severity:** High
- **Reachability:** Reachable -- called from the config upload handler
- **Construct:** YAML loader without a safe loader applied to an uploaded config file
- **Recommendation:** Upgrade to 5.4 and use safe_load.

### [MEDIUM] D2: lodash@4.17.15 — prototype pollution
- **Package / version:** lodash, **CVE:** unverified, **Severity:** Medium
- **Recommendation:** Upgrade.

### [LOW] D3: lodash@4.17.15 — ReDoS
- **Package / version:** lodash, **CVE:** unverified, **Severity:** Low
- **Recommendation:** Upgrade.
"""

SECRET_REPORT = """\
# Secret Scanning Report

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | AWS access key | `deploy/ci.yml:14` | config | Looks live | High |
| S2 | AWS access key | `deploy/ci.yml:90` | config | Looks live | High |

## 4. Detailed Findings

### [HIGH] S1: AWS access key in deploy/ci.yml
- **Location:** `deploy/ci.yml:14`
- **Evidence:** `TOKENJ4F2-NOT-A-REAL-SECRET-VALUE`
- **Exposure:** Anyone with repo read access.
- **Construct:** cloud access key hard-coded in a CI pipeline environment block
- **Remediation:** Rotate the key.

### [HIGH] S2: AWS access key in deploy/ci.yml
- **Location:** `deploy/ci.yml:90`
- **Evidence:** AKIAQQ...
- **Remediation:** Rotate the key.
"""


def test_sast_construct_is_extracted_and_absent_for_older_findings():
    assert extract_construct_by_id(SAST_REPORT) == {
        "F1": "SQL query built by string formatting with a request parameter, passed to a raw cursor execute"
    }
    rows = {row["id"]: row for row in sast_findings(SAST_REPORT)}
    assert rows["F1"]["construct"].startswith("SQL query built")
    assert rows["F2"]["construct"] == ""


def test_sca_rows_carry_ecosystem_advisory_and_construct():
    rows = {row["id"]: row for row in sca.findings_with_fingerprints(SCA_REPORT)}
    assert rows["D1"]["ecosystem"] == "PyPI"
    assert rows["D1"]["cve"] == "CVE-2020-14343"
    assert rows["D1"]["construct"] == "YAML loader without a safe loader applied to an uploaded config file"
    assert rows["D1"]["reachability_evidence"].startswith("Reachable")
    assert rows["D2"]["ecosystem"] == "npm"


def test_sca_fingerprint_ignores_version_so_an_unfixed_bump_is_the_same_finding():
    bumped = SCA_REPORT.replace("5.3", "5.3.1")
    before = {row["id"]: row["fingerprint"] for row in sca.findings_with_fingerprints(SCA_REPORT)}
    after = {row["id"]: row["fingerprint"] for row in sca.findings_with_fingerprints(bumped)}
    assert before["D1"] == after["D1"]


def test_sca_same_package_without_advisory_ids_does_not_collapse():
    rows = {row["id"]: row["fingerprint"] for row in sca.findings_with_fingerprints(SCA_REPORT)}
    assert rows["D2"] != rows["D3"]
    assert len(set(rows.values())) == 3


def test_sca_advisory_id_recognition():
    assert sca.is_advisory_id("CVE-2020-14343")
    assert sca.is_advisory_id("GHSA-p6mc-m468-83gw")
    assert sca.is_advisory_id("PYSEC-2026-2132")
    assert not sca.is_advisory_id("unverified")
    assert not sca.is_advisory_id("CVE-like prose")
    assert not sca.is_advisory_id(None)


def test_secret_evidence_is_re_redacted_even_when_the_model_overshares():
    rows = {row["id"]: row for row in secret_scanning.findings_with_fingerprints(SECRET_REPORT)}
    assert rows["S1"]["evidence"] == "TOKENJ4F..."
    assert "NOT-A-REAL-SECRET-VALUE" not in str(rows["S1"])
    assert rows["S2"]["evidence"] == "AKIAQQ..."


def test_redact_evidence_edge_cases():
    assert secret_scanning.redact_evidence(None) is None
    assert secret_scanning.redact_evidence("   ") is None
    assert secret_scanning.redact_evidence("...") is None
    assert secret_scanning.redact_evidence("changeme123") == "changeme..."


def test_secret_same_type_and_file_gets_line_buckets_without_a_workdir():
    rows = {row["id"]: row for row in secret_scanning.findings_with_fingerprints(SECRET_REPORT)}
    assert rows["S1"]["fingerprint"] != rows["S2"]["fingerprint"]
    assert rows["S1"]["location_file"] == "deploy/ci.yml"
    assert rows["S1"]["location_line"] == "14"
    assert rows["S1"]["construct"] == "cloud access key hard-coded in a CI pipeline environment block"


def test_secret_fingerprint_uses_the_code_region_when_the_repo_is_on_disk(tmp_path):
    (tmp_path / "deploy").mkdir()
    lines = [f"line {i}" for i in range(1, 101)]
    (tmp_path / "deploy" / "ci.yml").write_text("\n".join(lines), encoding="utf-8")
    with_repo = {r["id"]: r for r in secret_scanning.findings_with_fingerprints(SECRET_REPORT, workdir=tmp_path)}
    assert with_repo["S1"]["code_region_hash"] is not None
    # Shifting both secrets down by unrelated edits above them keeps the
    # region-hash identity even though the line numbers moved.
    (tmp_path / "deploy" / "ci.yml").write_text("\n".join(["new header"] * 5 + lines), encoding="utf-8")
    shifted = SECRET_REPORT.replace("ci.yml:14", "ci.yml:19").replace("ci.yml:90", "ci.yml:95")
    after = {r["id"]: r for r in secret_scanning.findings_with_fingerprints(shifted, workdir=tmp_path)}
    assert after["S1"]["fingerprint"] == with_repo["S1"]["fingerprint"]
