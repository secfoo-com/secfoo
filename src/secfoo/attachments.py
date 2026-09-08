"""Classifies a manually-uploaded assessment attachment by filename."""

from __future__ import annotations

from secfoo.docext import is_extractable

_AI_BOM_MARKERS = ("ai-bom", "aibom", "ai_bom")
_REPORT_SUFFIXES = (".md", ".html", ".htm")


def infer_attachment_kind(filename: str) -> str:
    lower = filename.lower()
    if any(marker in lower for marker in _AI_BOM_MARKERS):
        return "ai_bom"
    if lower.endswith(_REPORT_SUFFIXES):
        return "report"
    # A PDF/DOCX/PPTX is a vendor security document (SOC 2 report, ISO
    # cert, pen test report, questionnaire, ...) regardless of what
    # assessment it's attached to -- web/routes/assessments.py decides
    # whether to actually extract text from it and auto-trigger a
    # Third-Party Risk Assessment run based on the assessment's own type,
    # not this classifier.
    if is_extractable(filename):
        return "vendor_doc"
    return "other"
