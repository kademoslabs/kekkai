import hashlib

import pytest

from regulon.checklist import generate_checklist
from regulon.pdf import generate_pdf_bytes


@pytest.mark.regression
def test_pdf_hash_regression() -> None:
    checklist = generate_checklist("https://example.com", "support security.txt")
    pdf_bytes = generate_pdf_bytes(checklist)
    digest = hashlib.sha256(pdf_bytes).hexdigest()
    assert digest == "82c07a194e4deac4846a28e51fef8e5eb7bfacfbe74172a29a1e76677d88a8b4"
