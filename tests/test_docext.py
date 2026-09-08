from __future__ import annotations

from secfoo.docext import extract_text, is_extractable

# A minimal, hand-built, genuinely valid single-page PDF (not a mock/stub)
# whose content stream draws the literal text "Hello Vendor PDF" -- small
# enough to inline here, real enough that pypdf actually parses the object
# graph and extracts real text from it, not a fixture that merely looks
# like a PDF.
_MINIMAL_PDF_TEXT = "Hello Vendor PDF"
_MINIMAL_PDF_BYTES = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /MediaBox [0 0 300 144] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 58 >>
stream
BT /F1 24 Tf 10 100 Td ({_MINIMAL_PDF_TEXT}) Tj ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF
""".encode("latin-1")


def _write_pdf(tmp_path):
    path = tmp_path / "vendor.pdf"
    path.write_bytes(_MINIMAL_PDF_BYTES)
    return path


def _write_docx(tmp_path):
    import docx

    path = tmp_path / "vendor.docx"
    document = docx.Document()
    document.add_paragraph("SOC 2 Type II Report")
    document.add_paragraph("Audit period: 2025-01-01 to 2025-12-31")
    table = document.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Control"
    table.rows[0].cells[1].text = "Status"
    document.save(str(path))
    return path


def _write_pptx(tmp_path):
    from pptx import Presentation

    path = tmp_path / "vendor.pptx"
    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[1])
    slide.shapes.title.text = "Security Overview"
    slide.placeholders[1].text = "ISO 27001 certified since 2022"
    presentation.save(str(path))
    return path


def test_is_extractable_recognizes_supported_extensions():
    assert is_extractable("report.pdf") is True
    assert is_extractable("Report.PDF") is True
    assert is_extractable("report.docx") is True
    assert is_extractable("deck.pptx") is True
    assert is_extractable("notes.txt") is False
    assert is_extractable("archive.zip") is False


def test_extract_text_from_real_pdf(tmp_path):
    path = _write_pdf(tmp_path)
    text = extract_text(path)
    assert "Hello Vendor PDF" in text


def test_extract_text_from_real_docx(tmp_path):
    path = _write_docx(tmp_path)
    text = extract_text(path)
    assert "SOC 2 Type II Report" in text
    assert "Audit period: 2025-01-01 to 2025-12-31" in text
    # Table cells are extracted too, not just paragraphs.
    assert "Control" in text and "Status" in text


def test_extract_text_from_real_pptx(tmp_path):
    path = _write_pptx(tmp_path)
    text = extract_text(path)
    assert "Security Overview" in text
    assert "ISO 27001 certified since 2022" in text


def test_extract_text_returns_empty_string_for_unsupported_extension(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("plain text file")
    assert extract_text(path) == ""


def test_extract_text_returns_empty_string_for_malformed_pdf_rather_than_raising(tmp_path):
    path = tmp_path / "corrupt.pdf"
    path.write_bytes(b"%PDF-1.4\nnot actually a valid pdf structure")
    assert extract_text(path) == ""


def test_extract_text_returns_empty_string_for_malformed_docx_rather_than_raising(tmp_path):
    path = tmp_path / "corrupt.docx"
    path.write_bytes(b"this is not a zip file at all")
    assert extract_text(path) == ""


def test_extract_text_returns_empty_string_for_malformed_pptx_rather_than_raising(tmp_path):
    path = tmp_path / "corrupt.pptx"
    path.write_bytes(b"this is not a zip file at all")
    assert extract_text(path) == ""
