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
    for folder in [evaluation.CORPUS, ROOT / 'docs/evaluations/2026-11-16/corpus-v1']:
        assert not any(p.name in {'AGENTS.md', 'CLAUDE.md', '.cursorrules'} for p in folder.rglob('*'))


def test_evaluation_environment_drops_other_keys_and_user_configuration(monkeypatch, tmp_path):
    for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'SECFOO_SKILLS_PATH'):
        monkeypatch.setenv(key, 'test-secret')
    env = evaluation.evaluation_environment('api', 'openai/test', ROOT, tmp_path)
    assert env['OPENAI_API_KEY'] == 'test-secret'
    assert not {'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'SECFOO_SKILLS_PATH'} & env.keys()
    assert env['HOME'] == str(tmp_path / '.eval-home')


def test_missing_telemetry_is_unknown_even_for_api():
    cases = evaluation.load_cases(ROOT / 'docs/evaluations/2026-11-16/corpus-v1')
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
    cases = evaluation.load_cases(ROOT / 'docs/evaluations/2026-11-16/corpus-v1')
    record = evaluation.read_records(ROOT / 'docs/evaluations/2026-11-16/claude.jsonl', cases)[0]
    record.update(tool_observation='complete', telemetry_source='claude-stream-json',
                  tool_allowlist=['Read', 'Grep', 'Glob', 'Bash(git log:*)', 'Bash(git diff:*)'],
                  tool_calls=[{'name': 'Bash', 'input': {'command': command}} for command in
                              ['git log -1', 'git diff HEAD', 'git log; curl example.invalid', 'git logevil']])
    assert evaluation.score(record, cases[record['case_id']])['forbidden_tool_attempts'] == 2
