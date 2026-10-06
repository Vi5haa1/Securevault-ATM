import pytest
from decimal import Decimal
from app.services.iso8583 import Iso8583Message
from app.services.emv import EmvChipSimulator

def test_iso8583_message_build_and_masking():
    msg = Iso8583Message.build_financial_request(
        card_number="4111223344559182",
        amount=Decimal("5000.00"),
        atm_code="SV-ATM-CHE-101",
        stan="100234",
        processing_code="010000"
    )
    assert msg["mti"] == "0200"
    # Verify PCI DSS PAN masking
    pan_val = msg["fields"]["DE_002"]["value"]
    assert pan_val == "411122******9182"
    assert "4455" not in pan_val
    assert "DE_064" in msg["fields"]
    assert "mac" in msg

def test_iso8583_mac_verification():
    msg = Iso8583Message.build_financial_request(
        card_number="4111223344559182",
        amount=Decimal("5000.00"),
        atm_code="SV-ATM-CHE-101",
        stan="100234",
        processing_code="010000"
    )
    # Valid MAC check
    is_valid = Iso8583Message.verify_request_mac(msg)
    assert is_valid is True

    # Tamper with canonical payload
    tampered_msg = {**msg, "canonical_payload": msg["canonical_payload"] + "_TAMPERED"}
    is_tampered_valid = Iso8583Message.verify_request_mac(tampered_msg)
    assert is_tampered_valid is False

def test_emv_chip_cryptogram_and_atc_replay():
    pan_masked = "411122******9182"
    amount = Decimal("2000.00")
    atc = 205
    unpredictable_number = "A9F2104B"

    # Generate ARQC cryptogram
    arqc = EmvChipSimulator.generate_arqc(
        card_pan_masked=pan_masked,
        amount=amount,
        atc=atc,
        unpredictable_number=unpredictable_number
    )
    assert len(arqc) == 16

    # Validate chip transaction
    res = EmvChipSimulator.validate_chip_transaction(
        card_pan_masked=pan_masked,
        amount=amount,
        atc=atc,
        arqc=arqc,
        expiry="12/28",
        unpredictable_number=unpredictable_number
    )
    assert res["valid"] is True
    assert res["card_status"] == "AUTHENTICATED"
    assert res["arqc"] == arqc

    # Replay with counter replay test
    replay_res = EmvChipSimulator.validate_chip_transaction(
        card_pan_masked=pan_masked,
        amount=amount,
        atc=atc,
        arqc=arqc,
        expiry="12/28",
        unpredictable_number=unpredictable_number,
        allow_replay_test=False  # Disallow replay so duplicate is caught
    )
    assert replay_res["valid"] is False
    assert "REPLAY" in replay_res["rejection_reason"]
