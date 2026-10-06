import pytest
from app.services.pin_policy import PinPolicyService


def test_valid_pins():
    valid, errors = PinPolicyService.validate_pin("4826")
    assert valid is True
    assert len(errors) == 0

    valid, errors = PinPolicyService.validate_pin("739158")
    assert valid is True
    assert len(errors) == 0


def test_reject_weak_and_sequential_pins():
    # Common weak
    valid, errors = PinPolicyService.validate_pin("1234")
    assert valid is False
    assert any("too common" in e or "ascending" in e for e in errors)

    # All identical
    valid, errors = PinPolicyService.validate_pin("0000")
    assert valid is False
    assert any("identical" in e or "too common" in e for e in errors)

    # Descending sequence
    valid, errors = PinPolicyService.validate_pin("9876")
    assert valid is False
    assert any("descending" in e for e in errors)

    # Calendar year
    valid, errors = PinPolicyService.validate_pin("1998")
    assert valid is False
    assert any("calendar year" in e for e in errors)


def test_pin_length_and_non_digits():
    valid, errors = PinPolicyService.validate_pin("12")
    assert valid is False
    assert any("digits long" in e for e in errors)

    valid, errors = PinPolicyService.validate_pin("abcd")
    assert valid is False
    assert any("only digits" in e for e in errors)
