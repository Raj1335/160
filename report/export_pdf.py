"""Export a rendered HTML report as a PDF using WeasyPrint."""

from __future__ import annotations

from pathlib import Path


def export_pdf(html_path: str) -> str:
    """Render a PDF beside an existing HTML report and return its path."""
    source = Path(html_path)
    if not source.is_file():
        raise FileNotFoundError(f"HTML report does not exist: {source}")
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError(
            "PDF export is enabled, but WeasyPrint is not installed."
        ) from exc

    pdf_path = source.with_suffix(".pdf")
    HTML(filename=str(source), base_url=str(source.parent)).write_pdf(
        str(pdf_path)
    )
    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        raise OSError(f"WeasyPrint did not create a valid PDF: {pdf_path}")
    return str(pdf_path)
