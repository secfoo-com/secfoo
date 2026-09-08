# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the secfoo standalone binary. Build with:

    pyinstaller packaging/secfoo.spec --distpath dist/binary

A .spec file (rather than plain --add-data CLI flags) matters here mainly
because Analysis(datas=[...]) takes (src, dest) tuples, sidestepping the
--add-data "src:dest" vs "src;dest" separator difference between Unix and
Windows that a single cross-platform CI build command would otherwise have
to special-case per OS.

Hidden imports and the datas list were derived empirically (Aug 2026) by
building a real binary and exercising `secfoo run` + `secfoo serve` end to
end -- PyInstaller's static import scanner misses uvicorn's dynamic
protocol/loop selection, and every one of the 5 datas entries below is a
place secfoo loads package data via a `Path(__file__).parent`-relative
path at runtime (grepped exhaustively across src/secfoo).
"""

from pathlib import Path

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src" / "secfoo"

datas = [
    (str(SRC / "web" / "templates"), "secfoo/web/templates"),
    (str(SRC / "web" / "static"), "secfoo/web/static"),
    (str(SRC / "skills" / "definitions"), "secfoo/skills/definitions"),
    (str(SRC / "storage" / "schema.sql"), "secfoo/storage"),
    (str(SRC / "storage" / "schema_indexes.sql"), "secfoo/storage"),
    (str(SRC / "config.example.toml"), "secfoo"),
]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
]

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT / "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="secfoo",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
)
