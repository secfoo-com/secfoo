"""Guards against documentation drifting away from the code it describes."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_release_docs_do_not_claim_tag_push_trigger() -> None:
    """The release workflow is workflow_dispatch only, so the docs must not say otherwise."""
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    triggers = workflow.split("\non:\n", 1)[1].split("\n\n", 1)[0]
    assert "workflow_dispatch" in triggers
    assert not re.search(r"^\s{2}push:", triggers, re.MULTILINE)

    reference = (ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
    assert "tag push" not in reference.replace("not triggered by tag pushes", "")
