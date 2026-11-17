"""Coverage-guided fuzzing of secfoo's document parsers (docext) with Atheris.

docext parses PDF, DOCX, and PPTX files for vendor security documents.
Extraction must never raise an unhandled exception or crash on malformed data (#118).

Run locally (Linux or macOS with clang):

    pip install atheris
    python fuzz/fuzz_docext.py -max_total_time=60

Any crash is written to the current directory as crash-<sha1>; reproduce
with `python fuzz/fuzz_docext.py crash-<sha1>`.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from secfoo.docext import extract_text, is_extractable

EXTENSIONS = [".pdf", ".docx", ".pptx"]


def test_one_input(data: bytes) -> None:
    if not data:
        return
    # Use the first byte to pick the extension
    ext = EXTENSIONS[data[0] % len(EXTENSIONS)]
    content = data[1:]

    assert is_extractable(f"sample{ext}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_file = Path(tmp_dir) / f"fuzz_input{ext}"
        tmp_file.write_bytes(content)
        # extract_text must never raise unhandled exceptions on malformed files
        result = extract_text(tmp_file)
        assert isinstance(result, str)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
