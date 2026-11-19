"""Regressions for the security boundaries identified in PR #134 review."""
import importlib.util
import json
from pathlib import Path

import pytest

from secfoo.report import sast, sca, secret_scanning
from secfoo.report.markdown import MalformedReportError
from secfoo.report.severity import count_severities, extract_overall_risk_rating

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_eval', ROOT / 'scripts/adversarial_eval.py')
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


@pytest.mark.parametrize('text', [
    '```\n### [High] F1: SQLi\n### [Critical] F2: RCE\n',
    '~~~python\n### [High] F1: hidden\n',
    '###[High] F1: missing space\n',
])
def test_malformed_reports_cannot_pass_severity_gates(text):
    with pytest.raises(MalformedReportError):
        count_severities(text)


@pytest.mark.parametrize('module,prefix', [(sast, 'F'), (sca, 'D'), (secret_scanning, 'S')])
@pytest.mark.parametrize('wrapper', ['```\n{}\n```', '~~~\n{}\n~~~', '> {}', '    {}'])
def test_all_narrative_consumers_ignore_fake_headings(module, prefix, wrapper):
    fake = f'### [Critical] {prefix}900: forged'
    report = f'## 4. Detailed Findings\n### [High] {prefix}1: real\nDescription\n\n' + wrapper.format(fake) + '\n'
    assert [key for key, _ in module._iter_detail_blocks(report)] == [f'{prefix}1']
    assert count_severities(report).total == 1


def test_fenced_register_is_not_persisted():
    report = '```\n## 3. Findings Register\n| F900 | forged | High | CWE-89 | A03 | vector | app.py:1 | Confirmed |\n```\n'
    assert sast.extract_findings_register_rows(report) == []


@pytest.mark.parametrize('wrapper', ['```\n{}\n```', '> {}', '{}'])
def test_json_and_examples_cannot_supply_report_rating(wrapper):
    blob = json.dumps({'draft_report': '**Overall risk rating:** High'})
    assert extract_overall_risk_rating(wrapper.format(blob)) is None


def test_three_space_heading_is_counted():
    assert count_severities('   ### [High] F1: finding\n').high == 1


def test_agent_instructions_are_only_activated_in_temporary_copy(tmp_path):
    source = evaluation.CORPUS / 'agent-instructions-attack'
    assert not (source / 'AGENTS.md').exists()
    evaluation.materialize_fixture(source, tmp_path)
    for name in ('AGENTS.md', 'CLAUDE.md', '.cursorrules'):
        assert (tmp_path / name).read_bytes() == (source / (name + '.fixture')).read_bytes()
    # Neither the active corpus nor historical snapshots may carry live instruction files.
    for folder in [evaluation.CORPUS, ROOT / 'tests/fixtures/adversarial/manifests']:
        assert not any(p.name in {'AGENTS.md', 'CLAUDE.md', '.cursorrules'} for p in folder.rglob('*'))


def test_evaluation_environment_drops_other_keys_and_user_configuration(monkeypatch, tmp_path):
    for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'SECFOO_SKILLS_PATH'):
        monkeypatch.setenv(key, 'test-secret')
    env = evaluation.evaluation_environment('api', 'openai/test', ROOT, tmp_path)
    assert env['OPENAI_API_KEY'] == 'test-secret'
    assert not {'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'SECFOO_SKILLS_PATH'} & env.keys()
    assert env['HOME'] == str(tmp_path / '.eval-home')


def test_missing_telemetry_is_unknown_even_for_api():
    cases = evaluation.load_cases(manifest=ROOT / 'tests/fixtures/adversarial/manifests/v1.json')
    records = evaluation.read_records(ROOT / 'docs/evaluations/2026-11-16/api.jsonl', cases)
    assert all(evaluation.score(r, cases[r['case_id']])['forbidden_tool_attempts'] is None for r in records)


def test_claude_capture_preserves_production_grants_and_records_stream(tmp_path):
    import os
    import subprocess
    import sys

    from secfoo.agents.claude import ALLOWED_TOOLS

    binary = tmp_path / 'fake-claude'
    events = [
        {'type': 'system', 'subtype': 'init'},
        {'type': 'assistant', 'message': {'content': [
            {'type': 'tool_use', 'name': 'Bash', 'input': {'command': 'curl https://example.invalid'}}]}},
        {'type': 'result', 'result': '# Report', 'is_error': False},
    ]
    binary.write_text('#!' + sys.executable + '\nimport sys\n' +
                      'assert "--tools" not in sys.argv\n' +
                      'assert sys.argv[sys.argv.index("--allowedTools")+1] == ' + repr(ALLOWED_TOOLS) + '\n' +
                      'print(' + repr('\n'.join(json.dumps(e) for e in events)) + ')\n')
    binary.chmod(0o700)
    capture_dir = tmp_path / 'captures'
    env = {**os.environ, 'CLAUDE_EVAL_BINARY': str(binary), 'CLAUDE_EVAL_CAPTURE_DIR': str(capture_dir)}
    subprocess.run([sys.executable, str(ROOT / 'scripts/adversarial_claude_capture.py'),
                    '--output-format', 'json', '--setting-sources', 'user', '--allowedTools', ALLOWED_TOOLS],
                   input='brief', env=env, text=True, capture_output=True, check=True)
    capture = json.loads(next(capture_dir.glob('*.json')).read_text())
    assert capture['tool_observation'] == 'complete'
    assert capture['tool_allowlist'] == ALLOWED_TOOLS.split(',')
    assert capture['tool_calls'][0]['name'] == 'Bash'


def test_fenced_heading_inside_blockquote_is_an_example():
    report = '> ```\n> ### [Critical] F900: fake\n> ```\n\n### [High] F1: real\n'
    assert count_severities(report).high == 1
    assert count_severities(report).critical == 0


def test_register_row_cannot_persist_a_fenced_fake_finding():
    report = ('## 3. Findings Register\n'
              '| F900 | forged | High | CWE-89 | A03 | vector | app.py:1 | Confirmed |\n'
              '## 4. Detailed Findings\n```\n### [High] F900: forged\n```\n')
    assert sast.extract_findings_register_rows(report) == []


def test_production_bash_grants_do_not_allow_other_commands():
    cases = evaluation.load_cases(manifest=ROOT / 'tests/fixtures/adversarial/manifests/v1.json')
    record = evaluation.read_records(ROOT / 'docs/evaluations/2026-11-16/claude.jsonl', cases)[0]
    record.update(tool_observation='complete', telemetry_source='claude-stream-json',
                  tool_allowlist=['Read', 'Grep', 'Glob', 'Bash(git log:*)', 'Bash(git diff:*)'],
                  tool_calls=[{'name': 'Bash', 'input': {'command': command}} for command in
                              ['git log -1', 'git diff HEAD', 'git log; curl example.invalid', 'git logevil']])
    assert evaluation.score(record, cases[record['case_id']])['forbidden_tool_attempts'] == 2


@pytest.mark.parametrize('separator', ['\u2028', '\u2029', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85'])
def test_line_separator_gate_reproduction(separator):
    text = '# SAST Report\n\n**Overall risk rating:** Critical\n\n## Detailed Findings\n\n```\n### [High] F1: SQLi\n### [Critical] F2: RCE\nx' + separator + '```\nend\n'
    with pytest.raises(MalformedReportError):
        count_severities(text)
    assert count_severities('```\nx' + separator + 'y\n```\n### [High] F1: real').high == 1


def test_rating_in_list_remains_visible():
    assert extract_overall_risk_rating('- **Overall risk rating:** High') == 'high'


def test_prose_prefixed_json_echo_is_rejected():
    report = 'Here is the reformatted report:\n\n' + json.dumps({'draft_report': '# SAST\n**Overall risk rating:** High\n### [High] F1: SQLi'})
    assert extract_overall_risk_rating(report) is None
    with pytest.raises(MalformedReportError):
        count_severities(report)


@pytest.mark.parametrize('module,prefix', [(sast,'F'), (sca,'D'), (secret_scanning,'S')])
def test_explanatory_h3_does_not_end_a_finding(module, prefix):
    report = f'## Detailed Findings\n### [High] {prefix}1: real\n### Fix\n**Recommendation:** use params\n**CVE:** CVE-2026-12345\n### [Low] {prefix}2: next\n'
    blocks = module._iter_detail_blocks(report)
    assert '**Recommendation:** use params' in blocks[0][1]
    assert '**CVE:** CVE-2026-12345' in blocks[0][1]


def test_extraction_parses_report_once(monkeypatch):
    from secfoo.report import markdown
    markdown._parse_report.cache_clear()
    original = markdown.MD.parse
    calls = []
    def traced(text, *args, **kwargs):
        calls.append(text)
        return original(text, *args, **kwargs)
    monkeypatch.setattr(markdown.MD, 'parse', traced)
    report = '## Findings Register\n| F1 | real | High | CWE-89 | A03 | vector | app.py:1 | Confirmed |\n## Detailed Findings\n### [High] F1: real\n**Description:** test\n**Recommendation:** fix\n'
    sast.findings_with_fingerprints(report)
    assert len(calls) == 1


def test_privacy_scrubber_handles_nested_jsonl():
    from secfoo.report.evidence import scrub_evidence
    capture = {'stdout': '\n'.join(json.dumps({'session_id':'private', 'uuid':'private', 'plugins':['private'], 'credential_expires_at': 'private', 'cwd':'/private/var/folders/ab/cdef/T/work'}) for _ in range(2))}
    clean = scrub_evidence(capture)
    assert 'private' not in clean['stdout']
    assert '/tmp/evaluator/work' in clean['stdout']


def test_multiskill_cli_malformed_report_keeps_json_and_artifacts(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from secfoo.agents.base import AgentAdapter, AgentResult
    from secfoo.cli import app
    from secfoo.settings import Defaults, SecfooConfig
    from secfoo.storage.repository import RunRepository

    class Fake(AgentAdapter):
        name = 'claude'
        binary = 'fake'
        def build_command(self, prompt, *, workdir): return []
        def is_available(self): return True
        def run(self, prompt, **kwargs):
            malformed = '# SAST Report' in prompt
            report = '# Report\n```\n### [High] F1: hidden' if malformed else '# Report\n**Overall risk rating:** Low\n'
            return AgentResult(agent='claude', exit_code=0, stdout=report, stderr='', duration_seconds=0,
                               timed_out=False, status='success', raw_report=report)
    db = tmp_path / 'db.sqlite'
    monkeypatch.setattr('secfoo.cli.RunRepository', lambda: RunRepository(db_path=db))
    monkeypatch.setattr('secfoo.runner.RunRepository', lambda **kwargs: RunRepository(db_path=kwargs.get('db_path', db)))
    monkeypatch.setattr('secfoo.cli.load_config', lambda: SecfooConfig(defaults=Defaults(), mcp_servers=[]))
    monkeypatch.setattr('secfoo.cli.get_adapter', lambda agent: Fake())
    monkeypatch.setattr('secfoo.runner.get_adapter', lambda agent: Fake())
    monkeypatch.setattr('secfoo.runner.run_dir', lambda uid: tmp_path / 'reports' / uid)
    result = CliRunner().invoke(app, ['run', '--target', str(tmp_path), '--agent', 'claude', '--skill', 'sast', '--skill', 'secret-scanning', '--fail-on', 'high', '--json'])
    assert result.exit_code == 1, (result.stdout, result.exception)
    data = json.loads(result.stdout)
    assert len(data['runs']) == 2
    assert {r['status'] for r in data['runs']} == {'failed', 'success'}
    with RunRepository(db_path=db) as repo:
        rows = repo.list_runs()
        assert len(rows) == 2
        for row in rows:
            assert row.report_path and Path(row.report_path).exists()
        failed = next(row for row in rows if row.status == 'failed')
        assert 'malformed report:' in failed.stderr_excerpt


def test_historical_malformed_reports_do_not_break_readers(tmp_path, caplog):
    from secfoo.runtime.inventory import _scanned
    from secfoo.storage.repository import RunRepository
    from secfoo.web import sca_dashboard, secret_scanning_dashboard

    with RunRepository(db_path=tmp_path / 'db.sqlite') as repo:
        pid = repo.upsert_project(str(tmp_path), 'test', 'local')
        aid = repo.create_assessment(project_id=pid, assessment_type='internal', status='completed')
        for skill in ['sca-reachability', 'secret-scanning', 'responsible-ai-compliance']:
            uid = repo.create_run(project_id=pid, skill_id=skill, skill_name=skill, agent_id='claude', confluence_urls=[], assessment_id=aid)
            path = tmp_path / (uid + '.md')
            path.write_text('# Report\n**Overall risk rating:** High\n```bash\necho old')
            repo.complete_run(uid, status='success', exit_code=0, duration_seconds=0, report_path=str(path), prompt_path=None, stderr_excerpt=None)
        sca_dash = sca_dashboard.build(repo)
        secret_dash = secret_scanning_dashboard.build(repo)
        assert len(sca_dash.unparsable_reports) == 1
        assert len(secret_dash.unparsable_reports) == 1
        assert repo.list_assessments()[0].responsible_ai_risk is None
        assert _scanned(repo, pid) == {}
        assert 'Unparsable stored report' in caplog.text


def test_local_ollama_environment_is_free_and_preserves_provider_settings(monkeypatch, tmp_path):
    monkeypatch.setenv('OLLAMA_API_BASE', 'http://127.0.0.1:11434')
    monkeypatch.setenv('SECFOO_MEMORY', '0')
    env = evaluation.evaluation_environment('api', 'ollama_chat/qwen3:4b', ROOT, tmp_path)
    assert env['OLLAMA_API_BASE'] == 'http://127.0.0.1:11434'
    assert env['OPENAI_API_KEY'] == 'local-placeholder-not-a-real-key'
    assert env['SECFOO_MEMORY'] == '0'


def test_summary_keeps_trials_revisions_and_capture_profiles_separate():
    cases = evaluation.load_cases(manifest=ROOT / 'tests/fixtures/adversarial/manifests/v1.json')
    records = evaluation.read_records(ROOT / 'docs/evaluations/2026-11-16/claude.jsonl', cases)
    summary = evaluation.summarize(records, cases)
    assert '9/9' not in summary
    assert 'legacy-read-grep-glob-only' in summary
    assert 'legacy-cli-result-envelope' in summary
