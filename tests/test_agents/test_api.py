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


GOOD_REPORT = "# SAST Report\n\n## Summary\nAll good.\n**Overall risk rating:** Low."


def _response(content, prompt_tokens=1200, completion_tokens=300):
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=content))],
        usage=types.SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


def _fake_litellm(monkeypatch, *, completion=None, cost=0.0123):
    module = types.SimpleNamespace()
    module.calls = []

    def _completion(**kwargs):
        module.calls.append(kwargs)
        if completion is not None:
            return completion(**kwargs)
        return _response(GOOD_REPORT)

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
    # Not "binary_not_found" -- this adapter has no CLI binary to miss in
    # the first place; what's missing is a key (SECFOO-35).
    assert result.status == "not_configured"
    assert "OPENAI_API_KEY" in result.stderr


def test_run_success_returns_report_and_usage(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SECFOO_API_MODEL", "openai/test-model")
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    fake = _fake_litellm(monkeypatch)

    result = ApiAdapter().run("Review this.", workdir=tmp_path)

    assert result.status == "success"
    assert result.raw_report == GOOD_REPORT
    assert result.input_tokens == 1200
    assert result.output_tokens == 300
    assert result.cost_usd == pytest.approx(0.0123)
    assert len(fake.calls) == 1  # a complete report needs no reformat
    call = fake.calls[0]
    assert call["model"] == "openai/test-model"
    assert call["num_retries"] == api.NUM_RETRIES
    content = call["messages"][0]["content"]
    assert content.startswith("Review this.")
    assert "===== FILE: app.py =====" in content


# ---------- #32: pre-flight prompt-size cap ----------


def _api_target(tmp_path, monkeypatch, *, source_chars=40_000):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    (tmp_path / "big.py").write_text("x" * source_chars, encoding="utf-8")


def test_prompt_over_max_input_tokens_fails_before_anything_is_sent(tmp_path, monkeypatch):
    _api_target(tmp_path, monkeypatch)  # ~40k chars -> ~10k tokens by the char estimate
    fake = _fake_litellm(monkeypatch)
    adapter = ApiAdapter()
    adapter.configure_max_input_tokens(1_000)

    result = adapter.run("Review this.", workdir=tmp_path)

    assert result.status == "failed"
    assert fake.calls == []  # nothing sent, nothing billed
    assert "over the max_input_tokens limit of 1,000" in result.stderr
    assert "Prompt is about 10," in result.stderr  # says how large it was
    assert "--max-input-tokens" in result.stderr  # and which knob applies
    assert result.cost_usd is None and result.input_tokens is None


def test_prompt_under_max_input_tokens_runs_normally(tmp_path, monkeypatch):
    _api_target(tmp_path, monkeypatch, source_chars=400)
    fake = _fake_litellm(monkeypatch)
    adapter = ApiAdapter()
    adapter.configure_max_input_tokens(100_000)

    result = adapter.run("Review this.", workdir=tmp_path)

    assert result.status == "success"
    assert len(fake.calls) == 1


def test_no_max_input_tokens_means_no_check(tmp_path, monkeypatch):
    _api_target(tmp_path, monkeypatch)
    fake = _fake_litellm(monkeypatch)
    fake.token_counter = lambda **kw: pytest.fail("must not count without a limit")

    assert ApiAdapter().run("Review this.", workdir=tmp_path).status == "success"


def test_max_input_tokens_uses_litellms_tokenizer_for_the_model(tmp_path, monkeypatch):
    _api_target(tmp_path, monkeypatch, source_chars=400)
    monkeypatch.setenv("SECFOO_API_MODEL", "openai/test-model")
    fake = _fake_litellm(monkeypatch)
    seen = {}

    def token_counter(model, messages):
        seen["model"] = model
        return 5_000  # tokenizer says far more than the char estimate would

    fake.token_counter = token_counter
    adapter = ApiAdapter()
    adapter.configure_max_input_tokens(4_000)

    result = adapter.run("Review this.", workdir=tmp_path)

    assert result.status == "failed"
    assert seen["model"] == "openai/test-model"
    assert "about 5,000 input tokens" in result.stderr
    assert fake.calls == []


def test_estimate_falls_back_to_four_chars_per_token_when_the_tokenizer_fails():
    broken = types.SimpleNamespace(token_counter=lambda **kw: (_ for _ in ()).throw(ValueError("unknown model")))
    messages = [{"role": "user", "content": "a" * 401}]
    assert api.estimate_input_tokens(broken, "x/unknown", messages) == 101  # ceil(401 / 4)


@pytest.mark.parametrize("bad", [0, -5, True, 1.5, "10"])
def test_configure_max_input_tokens_rejects_non_positive_integers(bad):
    with pytest.raises(ValueError, match="positive integer"):
        ApiAdapter().configure_max_input_tokens(bad)


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


def test_incomplete_report_is_reformatted_once_without_resending_source(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    (tmp_path / "app.py").write_text("print('hi')", encoding="utf-8")
    replies = iter([_response("### [HIGH] SQL injection in app.py"), _response(GOOD_REPORT, 400, 100)])
    fake = _fake_litellm(monkeypatch, completion=lambda **kwargs: next(replies))

    result = ApiAdapter().run("Review this.", workdir=tmp_path)

    assert result.status == "success"
    assert result.raw_report == GOOD_REPORT
    assert len(fake.calls) == 2
    fix_request = fake.calls[1]["messages"][0]["content"]
    assert "SQL injection in app.py" in fix_request  # the draft is passed back
    assert "===== FILE: app.py =====" not in fix_request  # the source is not
    assert result.input_tokens == 1600  # usage and cost add up across both calls
    assert result.output_tokens == 400
    assert result.cost_usd == pytest.approx(0.0246)


def test_reformat_is_attempted_only_once(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = _fake_litellm(monkeypatch, completion=lambda **kwargs: _response("no rating here"))

    result = ApiAdapter().run("prompt", workdir=tmp_path)

    assert result.status == "success"
    assert result.raw_report == "no rating here"
    assert len(fake.calls) == api.MAX_ATTEMPTS


def test_selected_model_overrides_api_environment_without_changing_it(tmp_path, monkeypatch):
    import os

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SECFOO_API_MODEL", "environment-model")
    (tmp_path / "app.py").write_text("pass\n")
    fake = _fake_litellm(monkeypatch)
    adapter = ApiAdapter()
    adapter.configure_model("selected-model")
    assert adapter.run("Review this.", workdir=tmp_path).status == "success"
    assert fake.calls[0]["model"] == "selected-model"
    assert os.environ["SECFOO_API_MODEL"] == "environment-model"
