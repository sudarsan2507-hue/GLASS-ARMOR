"""Functional tests for the license key module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import datetime
import importlib.util
import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent
TARGET = os.environ.get("PQGATE_TARGET", str(HERE / "original.py"))
_spec = importlib.util.spec_from_file_location("target", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

TODAY = datetime.date(2027, 6, 1)


@pytest.fixture(scope="module")
def vendor():
    return mod.generate_keypair()


def test_issue_and_verify(vendor):
    lic = mod.issue_license(vendor[1], "ACME GmbH", "photo-pro", "2027-12-31", seats=5)
    assert isinstance(lic, str) and lic.isascii()
    info = mod.verify_license(vendor[0], lic, "photo-pro", today=TODAY)
    assert info == {"customer": "ACME GmbH", "product": "photo-pro", "expires": "2027-12-31", "seats": 5}


def test_default_seats(vendor):
    lic = mod.issue_license(vendor[1], "Bob", "photo-pro", "2027-12-31")
    assert mod.verify_license(vendor[0], lic, "photo-pro", today=TODAY)["seats"] == 1


def test_expired_license_rejected(vendor):
    lic = mod.issue_license(vendor[1], "ACME GmbH", "photo-pro", "2027-01-31")
    assert mod.verify_license(vendor[0], lic, "photo-pro", today=TODAY) is None


def test_wrong_product_rejected(vendor):
    lic = mod.issue_license(vendor[1], "ACME GmbH", "photo-lite", "2027-12-31")
    assert mod.verify_license(vendor[0], lic, "photo-pro", today=TODAY) is None


def test_edited_license_rejected(vendor):
    lic = mod.issue_license(vendor[1], "ACME GmbH", "photo-pro", "2027-12-31")
    i = len(lic) // 3
    edited = lic[:i] + ("A" if lic[i] != "A" else "B") + lic[i + 1:]
    assert mod.verify_license(vendor[0], edited, "photo-pro", today=TODAY) is None


def test_other_vendor_rejected(vendor):
    _, other_private = mod.generate_keypair()
    lic = mod.issue_license(other_private, "Mallory", "photo-pro", "2099-12-31", seats=999)
    assert mod.verify_license(vendor[0], lic, "photo-pro", today=TODAY) is None


@pytest.mark.parametrize("bad", ["", "HELLO", "LIC9-AAAA", "LIC2-!!!!", "LIC1-AAAAAAAA"])
def test_garbage_rejected(vendor, bad):
    assert mod.verify_license(vendor[0], bad, "photo-pro", today=TODAY) is None
