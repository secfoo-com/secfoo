"""Best-effort plain-text extraction from uploaded vendor documents (PDF/
DOCX/PPTX) for the Third-Party Risk Assessment skill. Never raises on a
malformed or unsupported file -- extraction failure degrades to an empty
string so an upload always succeeds even when its content can't be
analyzed; the original file is still stored as reference material either
way (see web/routes/assessments.py).

Deliberately pure-Python libraries only (pypdf, python-docx, python-pptx)
-- no system binaries (no poppler, no LibreOffice) so the Docker/
Kubernetes image needs no extra OS packages.

Known residual risk, accepted for now rather than silently claimed as
solved: these libraries fully load a file's internal structure into
memory (pypdf's page objects; python-docx/python-pptx's underlying
zipfile-based XML parsing). MAX_UPLOAD_BYTES bounds the raw file size, but
a small, deliberately crafted file with a high internal
compression/expansion ratio (a "zip bomb"-shaped .docx/.pptx, or a
pathological PDF object graph) could still cost more memory/CPU than its
file size implies. A stronger mitigation (subprocess isolation with a
hard resource/time limit) is a reasonable follow-up hardening item, not
built here. What is built (#118): a DOCX/PPTX whose archive would expand
past MAX_EXPANDED_BYTES, or holds more than MAX_ARCHIVE_MEMBERS entries, is
not parsed at all (zipfile never inflates a member past its declared
size, so the central directory is a real bound); and the upload route
refuses a file whose content does not match its extension
(content_matches_extension) before anything parses it.
"""

from __future__ import annotations

import logging
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".pptx"}

# Generous for a real vendor security document (SOC 2 reports, ISO
# certificates, and pen test reports are almost always well under this),
# while bounding the worst case of the residual risk noted above.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
# Every attachment, not only vendor documents, is capped at MAX_UPLOAD_BYTES
# (web/routes/assessments.py; web/security.py refuses a larger request
# before it is spooled to disk).

# A real 25 MB DOCX/PPTX expands to a few times its size; a zip bomb to
# thousands. Office documents have tens to a few hundred archive members.
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5_000

_OOXML_MAIN_PART = {".docx": "word/document.xml", ".pptx": "ppt/presentation.xml"}


class UnsafeArchiveError(ValueError):
    """A DOCX/PPTX whose archive is too large or too many-membered to parse."""


def content_matches_extension(path: Path) -> bool:
    """Whether the bytes at `path` are what its extension claims: a PDF
    header for .pdf, an Office Open XML archive with its main part for
    .docx/.pptx. True for any other extension (nothing to check). Never
    raises."""
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            with path.open("rb") as fh:
                # The spec allows junk before the header within the first 1 KiB.
                return b"%PDF-" in fh.read(1024)
        if suffix in _OOXML_MAIN_PART:
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
            return "[Content_Types].xml" in names and _OOXML_MAIN_PART[suffix] in names
    except Exception:  # noqa: BLE001 -- a predicate: anything unreadable is "no"
        # zipfile raises more than BadZipFile on hostile input:
        # NotImplementedError for an unsupported version or compression,
        # EOFError, struct.error, ... (found by fuzz/fuzz_docext.py).
        return False
    return True


def check_archive_bounds(path: Path) -> None:
    """Raise UnsafeArchiveError when the archive at `path` would expand past
    MAX_EXPANDED_BYTES or has more than MAX_ARCHIVE_MEMBERS entries."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError(f"{len(members)} archive members")
    expanded = sum(member.file_size for member in members)
    if expanded > MAX_EXPANDED_BYTES:
        raise UnsafeArchiveError(f"expands to {expanded} bytes")


def is_extractable(filename: str) -> bool:
    return Path(filename).suffix.lower() in SUPPORTED_EXTENSIONS


def extract_text(path: Path) -> str:
    """Extracts plain text from a PDF/DOCX/PPTX file at `path`. Returns
    "" for an unsupported extension, a file that fails to parse, or one
    with no extractable text (e.g. a scanned/image-only PDF -- this
    module does no OCR) -- callers treat "" as "nothing to analyze from
    this document," not as an error.
    """
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            return _extract_pdf(path)
        if suffix == ".docx":
            return _extract_docx(path)
        if suffix == ".pptx":
            return _extract_pptx(path)
    except Exception:  # noqa: BLE001 -- broad on purpose: the parsers raise many types; a bad file means ""
        logger.debug("text extraction failed for a %s file", suffix, exc_info=True)
        return ""
    return ""


def _extract_pdf(path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages = []
    for page in reader.pages:
        text = page.extract_text() or ""
        if text.strip():
            pages.append(text)
    return "\n\n".join(pages)


def _extract_docx(path: Path) -> str:
    import docx

    check_archive_bounds(path)

    document = docx.Document(str(path))
    parts = [p.text for p in document.paragraphs if p.text.strip()]
    for table in document.tables:
        for row in table.rows:
            cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
            if cells:
                parts.append(" | ".join(cells))
    return "\n".join(parts)


def _extract_pptx(path: Path) -> str:
    from pptx import Presentation

    check_archive_bounds(path)

    presentation = Presentation(str(path))
    parts = []
    for slide_number, slide in enumerate(presentation.slides, start=1):
        slide_parts = []
        for shape in slide.shapes:
            if shape.has_text_frame and shape.text_frame.text.strip():
                slide_parts.append(shape.text_frame.text)
            if shape.has_table:
                for row in shape.table.rows:
                    cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                    if cells:
                        slide_parts.append(" | ".join(cells))
        if slide_parts:
            parts.append(f"--- Slide {slide_number} ---\n" + "\n".join(slide_parts))
    return "\n\n".join(parts)
