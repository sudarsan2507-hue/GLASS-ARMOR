"""Functional tests for the invoice signing module.

The module under test is loaded from the PQGATE_TARGET env var (default: original.py),
so the same tests run on the original, the reference migration and every variant.
"""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

HERE = Path(__file__).parent
TARGET = os.environ.get("PQGATE_TARGET", str(HERE / "original.py"))
_spec = importlib.util.spec_from_file_location("target", TARGET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

INVOICE = {"number": "INV-2026-0042", "customer": "ACME GmbH", "currency": "EUR",
           "lines": [{"item": "consulting", "qty": 3, "unit_cents": 12000},
                     {"item": "travel", "qty": 1, "unit_cents": 8550}]}
NOTE = {"number": "CN-2026-0007", "refers_to": "INV-2026-0042", "amount_cents": 8550}


@pytest.fixture(scope="module")
def issuer():
    return mod.generate_keypair()


@pytest.fixture(scope="module")
def other():
    return mod.generate_keypair()


def test_sign_and_verify_invoice(issuer):
    signed = mod.sign_invoice(issuer[1], "seller-1", INVOICE)
    assert signed["issuer"] == "seller-1" and isinstance(signed["signature"], str)
    assert mod.verify_invoice(issuer[0], signed) is True


def test_original_dict_unchanged(issuer):
    before = copy.deepcopy(INVOICE)
    mod.sign_invoice(issuer[1], "seller-1", INVOICE)
    assert INVOICE == before


def test_sign_and_verify_credit_note(issuer):
    signed = mod.sign_credit_note(issuer[1], "seller-1", NOTE)
    assert mod.verify_credit_note(issuer[0], signed) is True


def test_changed_amount_rejected(issuer):
    signed = mod.sign_invoice(issuer[1], "seller-1", INVOICE)
    tampered = copy.deepcopy(signed)
    tampered["lines"][0]["qty"] = 30
    assert mod.verify_invoice(issuer[0], tampered) is False


def test_changed_issuer_rejected(issuer):
    signed = mod.sign_invoice(issuer[1], "seller-1", INVOICE)
    assert mod.verify_invoice(issuer[0], dict(signed, issuer="seller-2")) is False


def test_other_key_rejected(issuer, other):
    signed = mod.sign_invoice(other[1], "seller-1", INVOICE)
    assert mod.verify_invoice(issuer[0], signed) is False


def test_missing_signature_rejected(issuer):
    signed = mod.sign_invoice(issuer[1], "seller-1", INVOICE)
    del signed["signature"]
    assert mod.verify_invoice(issuer[0], signed) is False


def test_invoice_total():
    assert mod.invoice_total(INVOICE) == 3 * 12000 + 8550
