from __future__ import annotations

import io

from .models import Checklist


def generate_pdf_bytes(checklist: Checklist) -> bytes:
    lines = ["Regulon PSTI Checklist", f"Target: {checklist.url}", ""]
    for item in checklist.items:
        lines.append(f"{item.check_id}: {item.title} [{item.status.value}]")
        if item.evidence:
            lines.append(f"Evidence: {item.evidence}")
        lines.append("")

    content_stream = _build_content_stream(lines)
    return _wrap_pdf(content_stream)


def _build_content_stream(lines: list[str]) -> bytes:
    escaped_lines = [_escape_text(line) for line in lines]
    stream = io.StringIO()
    stream.write("BT /F1 12 Tf 14 TL 72 720 Td\n")
    for line in escaped_lines:
        stream.write(f"({line}) Tj\nT*\n")
    stream.write("ET")
    return stream.getvalue().encode("utf-8")


def _escape_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_pdf(stream_bytes: bytes) -> bytes:
    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        (
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >> endobj"
        ),
        (
            b"4 0 obj << /Length "
            + str(len(stream_bytes)).encode("ascii")
            + b" >> stream\n"
            + stream_bytes
            + b"\nendstream endobj"
        ),
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(buffer.tell())
        buffer.write(obj)
        buffer.write(b"\n")

    xref_start = buffer.tell()
    buffer.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    buffer.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n".encode("ascii"))
    buffer.write(f"startxref\n{xref_start}\n%%EOF\n".encode("ascii"))
    return buffer.getvalue()
