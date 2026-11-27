"""The recorder must never commit a credential it captured from a CLI."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "record_agent.py"
_spec = importlib.util.spec_from_file_location("secfoo_record_agent", SCRIPT)
record_agent = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(record_agent)


def test_redact_hides_vendor_keys():
    text = (
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz\n"
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n"
    )
    redacted = record_agent.redact(text)
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in redacted
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in redacted
    record_agent.ensure_no_secrets(redacted)


@pytest.mark.parametrize("text", [
    "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    'api_key: "abcdefghijklmnop1234567890"',
])
def test_ensure_no_secrets_refuses_to_save(text):
    with pytest.raises(ValueError, match="refusing to save recording"):
        record_agent.ensure_no_secrets(text)
