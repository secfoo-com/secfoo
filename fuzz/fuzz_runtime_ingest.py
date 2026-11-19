"""Fuzz runtime evidence ingest (#53, #66): an NDJSON batch -> stored events.

Input: the request body of `POST /api/runtime/v1/events` (or a file for
`secfoo runtime ingest`), after decompression.

Contract: what the API does with a batch -- decode, fill in app/env, then
`ingest_events` -- never raises. Every non-blank line is either stored or
listed as skipped with a reason, so one bad line can't roll back the rest
of the batch (which, through the API, was a 500).

    python fuzz/fuzz_runtime_ingest.py WORK fuzz/corpus/runtime_ingest -max_total_time=60
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from _common import main

from secfoo.runtime.api import _with_app_env
from secfoo.runtime.evidence import ingest_events
from secfoo.storage.repository import RunRepository

FINGERPRINT = "fuzz-fp-1"  # an SCA finding that exists, so valid hits are stored, not skipped

_repo = RunRepository(db_path=Path(tempfile.mkdtemp(prefix="secfoo-fuzz-ingest-")) / "fuzz.sqlite")
_project = _repo.upsert_project("/fuzz", "fuzz", "local")
_run = _repo.create_run(project_id=_project, skill_id="sca-reachability", skill_name="SCA", agent_id="claude",
                        confluence_urls=[])
_repo.upsert_sca_finding(project_id=_project, fingerprint=FINGERPRINT, run_id=_repo.get_run(_run).id,
                         current_ref="D1", package="fuzz-pkg", severity="High")


def check(data: bytes) -> None:
    lines = data.decode("utf-8", errors="replace").splitlines()  # exactly as post_events decodes
    lines = _with_app_env(lines, "fuzz-app", "fuzz-env")
    report = ingest_events(_repo.connection, _project, lines)
    non_blank = sum(1 for line in lines if line.strip())
    assert report.stored + len(report.skipped) == non_blank
    for number, reason in report.skipped:
        assert 1 <= number <= len(lines) and isinstance(reason, str) and reason


if __name__ == "__main__":
    main(check)
