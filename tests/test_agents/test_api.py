from __future__ import annotations

import sys
import types

import pytest

from secfoo.agents import api
from secfoo.agents.api import ApiAdapter, collect_files


@pytest.fixture
def no_keys(monkeypatch):
    for key in api.KEY_VARS:
        monkeypatch.delenv(key, raising=False)


def _fake_litellm(monkeypatch, *, completion=None, cost=0.0123):
    module = types.SimpleNamespace()
    module.calls = []

    def _completion(**kwargs):
        module.calls.append(kwargs)
        if completion is not None:
            return completion(**kwargs)
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=types.SimpleNamespace(content="# SAST Report"))],
            usage=types.SimpleNamespace(prompt_tokens=1200, completion_tokens=300),
        )

    def _completion_cost(completion_response):
        if isinstance(cost, Exception):
            raise cost
        return cost

    module.completion = _completion
    module.completion_cost = _completion_cost
    monkeypatch.setitem(sys.modules, "litellm", module)
    return module


def test_collect_files_labels_files_and_skips_excluded_paths(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("junk", encoding="utf-8")
    (tmp_path / "bundle.min.js").write_text("junk", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")

    text = collect_files(tmp_path)

    assert "===== FILE: app.py =====" in text
    assert "print('hi')" in text
    assert "dep.js" not in text
    assert "bundle.min.js" not in text
    assert "logo.png" not in text


def test_collect_files_rejects_a_target_over_the_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "MAX_TOTAL_CHARS", 50)
    (tmp_path / "big.py").write_text("x" * 100, encoding="utf-8")
    with pytest.raises(ValueError, match="too large"):
        collect_files(tmp_path)


def test_is_available_depends_on_an_api_key(no_keys, monkeypatch):
    assert ApiAdapter().is_available() is False
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    assert ApiAdapter().is_available() is True


def test_run_without_a_key_explains_what_to_set(no_keys, tmp_path):
    result = ApiAdapter().run("prompt", workdir=tmp_path)
    assert result.status == "binary_not_found"
    assert "OPENAI_API_KEY" in result.stderr


def test_run_success_returns_report_and_usage(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SECFOO_API_MODEL", "openai/test-model")
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    fake = _fake_litellm(monkeypatch)

    result = ApiAdapter().run("Review this.", workdir=tmp_path)

    assert result.status == "success"
    assert result.raw_report == "# SAST Report"
    assert result.input_tokens == 1200
    assert result.output_tokens == 300
    assert result.cost_usd == pytest.approx(0.0123)
    call = fake.calls[0]
    assert call["model"] == "openai/test-model"
    content = call["messages"][0]["content"]
    assert content.startswith("Review this.")
    assert "===== FILE: app.py =====" in content


def test_run_success_with_unpriced_model_keeps_tokens_and_leaves_cost_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    _fake_litellm(monkeypatch, cost=RuntimeError("no price for model"))

    result = ApiAdapter().run("prompt", workdir=tmp_path)

    assert result.status == "success"
    assert result.input_tokens == 1200
    assert result.cost_usd is None


def test_run_api_error_becomes_a_failed_run(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def _boom(**kwargs):
        raise RuntimeError("Incorrect API key provided")

    _fake_litellm(monkeypatch, completion=_boom)

    result = ApiAdapter().run("prompt", workdir=tmp_path)

    assert result.status == "failed"
    assert "Incorrect API key" in result.stderr
    assert result.raw_report == ""
    assert result.cost_usd is None


def test_run_strips_a_trailing_newline_from_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test\n")
    _fake_litellm(monkeypatch)

    result = ApiAdapter().run("prompt", workdir=tmp_path)

    assert result.status == "success"
    assert api.os.environ["OPENAI_API_KEY"] == "sk-test"


def test_run_without_litellm_installed_says_how_to_install_it(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setitem(sys.modules, "litellm", None)  # makes `import litellm` raise ImportError

    result = ApiAdapter().run("prompt", workdir=tmp_path)

    assert result.status == "failed"
    assert "secfoo[api]" in result.stderr
