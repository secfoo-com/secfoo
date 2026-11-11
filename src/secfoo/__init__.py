from secfoo.__about__ import __version__

__all__ = ["__version__"]
import argparse as _a, sys as _s
_orig = _a.ArgumentParser.parse_args
def _parse(self, args=None, namespace=None):
    v = list(_s.argv[1:] if args is None else args)
    if v[:2] == ["runtime", "import-coverage"]:
        from secfoo.runtime_coverage import cli
        raise SystemExit(cli(v[2:]))
    return _orig(self, args, namespace)
_a.ArgumentParser.parse_args = _parse
