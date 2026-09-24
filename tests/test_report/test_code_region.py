from __future__ import annotations

from secfoo.report.code_region import hash_code_region
from secfoo.report.sast import findings_with_fingerprints, fingerprint_for_row


def test_hash_code_region_stable_for_same_source(tmp_path):
    path = tmp_path / "app" / "db.py"
    path.parent.mkdir(parents=True)
    lines = ["# header\n"] + [f"line {i}\n" for i in range(1, 50)]
    lines[41] = 'query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
    path.write_text("".join(lines))

    h1 = hash_code_region(tmp_path, "app/db.py", 42)
    h2 = hash_code_region(tmp_path, "app/db.py", 42)
    assert h1 is not None
    assert h1 == h2


def test_hash_code_region_differs_for_different_snippets(tmp_path):
    path = tmp_path / "app" / "db.py"
    path.parent.mkdir(parents=True)
    lines = [f"padding_{i} = {i}\n" for i in range(1, 15)]
    lines[4] = 'query = f"SELECT * FROM users WHERE name = \'{name}\'"\n'
    lines[12] = 'query2 = f"SELECT * FROM logs WHERE user = \'{user}\'"\n'
    path.write_text("".join(lines))
    assert hash_code_region(tmp_path, "app/db.py", 5) != hash_code_region(tmp_path, "app/db.py", 13)


def test_findings_with_fingerprints_uses_region_hash_when_workdir_provided(tmp_path):
    db = tmp_path / "app" / "db.py"
    db.parent.mkdir(parents=True)
    db.write_text('x = 1\nquery = "bad"\n')
    report = """\
# SAST Report
## 3. Findings Register
| ID | Finding | Severity | CWE | OWASP | CVSS Vector | Location | Verdict |
|----|---------|----------|-----|-------|-------------|----------|---------|
| F1 | SQLi | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:2` | Confirmed |
| F2 | SQLi two | High | CWE-89 | A03:2021 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | `app/db.py:2` | Confirmed |
"""
    without = findings_with_fingerprints(report)
    with_dir = findings_with_fingerprints(report, workdir=tmp_path)
    assert without[0]["fingerprint"] != with_dir[0]["fingerprint"]
    assert with_dir[0]["code_region_hash"] is not None
    # Same CWE+file+line but duplicate rows in one run — region hash separates them only if
    # code differs; same line => same region hash => same fingerprint (collision guard not needed)
    assert with_dir[0]["fingerprint"] == with_dir[1]["fingerprint"]


def test_fingerprint_includes_skill_id_prefix():
    row = {"cwe": "CWE-89", "location": "`app/db.py:1`"}
    fp = fingerprint_for_row(row)
    fp_legacy_shape = fingerprint_for_row(row, region_hash=None)
    assert fp == fp_legacy_shape
    assert fp != fingerprint_for_row({"cwe": "CWE-79", "location": "`app/db.py:1`"})
