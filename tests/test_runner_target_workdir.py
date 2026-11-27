from __future__ import annotations

from pathlib import Path

import pytest

from secfoo.runner import _target_workdir
from secfoo.targets.resolver import ResolvedTarget, TargetKind


def test_local_target_yields_its_path(tmp_path: Path) -> None:
    target = ResolvedTarget(kind=TargetKind.LOCAL, path=tmp_path, display_name=str(tmp_path), is_temporary=False)
    with _target_workdir(target) as workdir:
        assert workdir == tmp_path


def test_local_target_without_path_raises_even_under_optimize() -> None:
    # Was an `assert`, which `python -O` strips (bandit B101, #114).
    target = ResolvedTarget(kind=TargetKind.LOCAL, path=None, display_name="somewhere", is_temporary=False)
    with pytest.raises(ValueError, match="has no path"), _target_workdir(target):
        pass
