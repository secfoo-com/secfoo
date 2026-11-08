from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

import pytest

from secfoo.runner import _project_display_name, _target_workdir
from secfoo.targets.forge import clone_forge
from secfoo.targets.resolver import TargetKind, TargetResolutionError, resolve_target


@pytest.mark.parametrize('url,kind', [
    ('https://gitlab.com/group/nested/repo.git', TargetKind.GITLAB),
    ('https://GITLAB.com/group/repo', TargetKind.GITLAB),
    ('git@gitlab.com:group/nested/repo.git', TargetKind.GITLAB),
    ('https://bitbucket.org/team/repo.git', TargetKind.BITBUCKET),
    ('git@bitbucket.org:team/repo', TargetKind.BITBUCKET),
])
def test_forge_targets(url, kind):
    target = resolve_target(url)
    assert target.kind is kind
    assert target.path is None
    assert target.is_temporary
    assert target.display_name == url
    assert _project_display_name(target) in {'group/nested/repo', 'group/repo', 'team/repo'}


def test_self_hosted(monkeypatch):
    monkeypatch.setenv('SECFOO_GITLAB_HOST', 'git.example.org:8443')
    target = resolve_target('https://git.example.org:8443/group/sub/repo')
    assert target.kind is TargetKind.GITLAB
    with pytest.raises(TargetResolutionError):
        resolve_target('https://git.example.org/group/repo')


@pytest.mark.parametrize('host', ['https://git.example.org', 'user:secret@git.example.org',
                                  'git.example.org/path', 'git.example.org:invalid', 'bitbucket.org'])
def test_bad_host_config(monkeypatch, host):
    monkeypatch.setenv('SECFOO_GITLAB_HOST', host)
    with pytest.raises(TargetResolutionError):
        resolve_target('https://gitlab.com/group/repo')


@pytest.mark.parametrize('url', [
    'https://gitlab.com/group', 'https://bitbucket.org/a/b/c',
    'https://gitlab.com/a/../b', 'https://gitlab.com/a//b',
    'https://gitlab.com/a/b?token=synthetic-secret',
    'https://user:synthetic-secret@gitlab.com/a/b',
    'https://user:synthetic-secret@github.com/a/b',
    'https://gitlab.com.evil.org/a/b', 'http://gitlab.com/a/b',
    'ssh://git@gitlab.com/a/b', 'https://gitlab.com/a/b#synthetic-secret',
])
def test_reject_invalid_url_without_leaking_input(url):
    with pytest.raises(TargetResolutionError) as exc:
        resolve_target(url)
    assert 'synthetic-secret' not in str(exc.value)


@pytest.mark.parametrize('kind,url,var,username', [
    (TargetKind.GITLAB, 'https://gitlab.com/a/b', 'SECFOO_GITLAB_TOKEN', 'oauth2'),
    (TargetKind.BITBUCKET, 'https://bitbucket.org/a/b', 'SECFOO_BITBUCKET_TOKEN', 'x-token-auth'),
])
def test_authenticated_clone_and_runner_dispatch(monkeypatch, kind, url, var, username):
    monkeypatch.setenv(var, 'synthetic-secret')
    captured = {}
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        captured['cmd'] = cmd
        captured['root'] = Path(cmd[-1]).parent
        env = kwargs['env']
        assert 'synthetic-secret' not in repr(cmd)
        assert kwargs['timeout'] == 600
        assert env['SECFOO_CLONE_TOKEN'] == 'synthetic-secret'
        assert env['SECFOO_CLONE_USER'] == username
        assert var not in env
        assert env['GIT_TERMINAL_PROMPT'] == '0'
        helper = Path(shlex.split(env['GIT_ASKPASS'])[1])
        assert 'synthetic-secret' not in helper.read_text()
        assert 'synthetic-secret' not in (helper.parent / 'askpass.py').read_text()
        for prompt, expected in [('Username for https://example.org', username),
                                 ('Password for https://example.org', 'synthetic-secret')]:
            result = real_run(shlex.split(env['GIT_ASKPASS']) + [prompt], env=env,
                              check=True, capture_output=True, text=True)
            assert result.stdout.strip() == expected
        Path(cmd[-1]).mkdir()
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr('secfoo.targets.forge.subprocess.run', fake_run)
    with _target_workdir(resolve_target(url)) as checkout:
        assert checkout.exists()
        assert not (checkout.parent / 'askpass.py').exists()
        assert captured['cmd'] == ['git', '-c', 'credential.helper=', '-c', 'http.followRedirects=false', 'clone', '--depth', '1', '--', url, str(checkout)]
    assert not captured['root'].exists()


@pytest.mark.parametrize('error', ['failure', 'timeout', 'missing', 'body'])
def test_cleanup_and_safe_errors(monkeypatch, error):
    root = []

    def fake_run(cmd, **kwargs):
        root.append(Path(cmd[-1]).parent)
        if error == 'failure':
            raise subprocess.CalledProcessError(128, cmd, stderr='synthetic-secret')
        if error == 'timeout':
            raise subprocess.TimeoutExpired(cmd, 5, stderr='synthetic-secret')
        if error == 'missing':
            raise FileNotFoundError('synthetic-secret')
        Path(cmd[-1]).mkdir()
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setenv('SECFOO_GITLAB_TOKEN', 'synthetic-secret')
    monkeypatch.setattr('secfoo.targets.forge.subprocess.run', fake_run)
    with (
        pytest.raises((TargetResolutionError, RuntimeError)) as exc,
        clone_forge('https://gitlab.com/a/b', kind=TargetKind.GITLAB),
    ):
        raise RuntimeError('body failure')
    assert 'synthetic-secret' not in str(exc.value)
    assert not root[0].exists()


@pytest.mark.parametrize('url', ['https://gitlab.com/a/b', 'git@gitlab.com:a/b'])
def test_no_token_uses_ordinary_git_auth(monkeypatch, url):
    monkeypatch.delenv('SECFOO_GITLAB_TOKEN', raising=False)
    commands = []

    def fake_run(cmd, **kwargs):
        commands.append(cmd)
        Path(cmd[-1]).mkdir()
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr('secfoo.targets.forge.subprocess.run', fake_run)
    with clone_forge(url, kind=TargetKind.GITLAB) as checkout:
        assert commands == [['git', 'clone', '--depth', '1', '--', url, str(checkout)]]


def test_invalid_gitlab_configuration_keeps_local_and_github_working(monkeypatch, tmp_path):
    monkeypatch.setenv('SECFOO_GITLAB_HOST', '[invalid')
    assert resolve_target(str(tmp_path)).kind is TargetKind.LOCAL
    assert resolve_target('https://github.com/org/repo').kind is TargetKind.GITHUB
    with pytest.raises(TargetResolutionError):
        resolve_target('https://gitlab.com/group/repo')
