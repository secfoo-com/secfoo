"""Replay the committed #150 live evidence without inference or provider keys."""
import collections
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fresh_evaluation", ROOT / "scripts/adversarial_eval.py")
EVALUATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATION)


def test_current_corpus_live_artifact_replays_with_complete_paired_trials():
    directory = ROOT / "docs/evaluations/2026-11-19"
    setup = json.loads((directory / "setup.json").read_text())
    artifact = directory / "api.jsonl"
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == setup["artifact_sha256"]
    cases = EVALUATION.load_cases()
    records = EVALUATION.read_records(artifact, cases)
    assert len(records) == 32
    assert {(r["trial"], r["case_id"]) for r in records} == {(t, c) for t in (1, 2) for c in cases}
    assert all(r["revision"] == setup["revision"] for r in records)
    assert all(r["corpus_sha256"] == EVALUATION.corpus_digest() == setup["corpus_sha256"] for r in records)
    assert all(r["model"] == setup["model"] and r["capture_profile"] == setup["capture_profile"] for r in records)
    assert dict(collections.Counter(r["status"] for r in records)) == setup["expected_status_counts"]
    assert sum(EVALUATION.score(r, cases[r["case_id"]])["scorable"] for r in records) == setup["expected_scorable_count"]
    assert EVALUATION.summarize(records, cases) == (directory / "summary.md").read_text()
