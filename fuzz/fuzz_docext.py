"""Fuzz uploaded-document text extraction (PDF / DOCX / PPTX).

Input: one selector byte (value % 3 picks .pdf, .docx or .pptx), then the
file's bytes. Seeds are small real documents, so libFuzzer mutates valid
structure rather than starting from noise.

Contract: extract_text returns a string -- "" for anything it can't read --
and never raises; an upload must always succeed (docext.py's own rule).
content_matches_extension, the upload route's type check (#118), returns a
bool and never raises either.
Each input must finish within PER_INPUT_SECONDS. On CI, libFuzzer's
-timeout and -rss_limit_mb additionally catch hangs and decompression bombs.

    python fuzz/fuzz_docext.py WORK fuzz/corpus/docext -max_total_time=60 -timeout=30
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from _common import main

from secfoo.docext import content_matches_extension, extract_text

SUFFIXES = (".pdf", ".docx", ".pptx")
PER_INPUT_SECONDS = 30.0
_DIR = Path(tempfile.mkdtemp(prefix="secfoo-fuzz-docext-"))


def split(data: bytes) -> tuple[str, bytes]:
    return SUFFIXES[data[0] % len(SUFFIXES)], data[1:]


def check(data: bytes) -> None:
    if not data:
        return
    suffix, body = split(data)
    path = _DIR / f"upload{suffix}"
    path.write_bytes(body)
    assert isinstance(content_matches_extension(path), bool)
    started = time.monotonic()
    text = extract_text(path)
    elapsed = time.monotonic() - started
    assert isinstance(text, str)
    assert elapsed < PER_INPUT_SECONDS, f"{suffix} extraction took {elapsed:.1f}s"


if __name__ == "__main__":
    main(check)
