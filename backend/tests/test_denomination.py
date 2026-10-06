import pytest
from app.services.denomination import DenominationService, DenominationDispenseError


def test_standard_dispense():
    inventory = {2000: 10, 500: 20, 200: 20, 100: 50}
    # Request 3700 -> 1x2000, 3x500, 1x200, 0x100
    plan = DenominationService.calculate_dispense(3700, inventory)
    
    total = sum(d["denomination"] * d["count"] for d in plan)
    assert total == 3700

    plan_dict = {d["denomination"]: d["count"] for d in plan}
    assert plan_dict[2000] == 1
    assert plan_dict[500] == 3
    assert plan_dict[200] == 1


def test_dispense_non_multiple_of_100():
    inventory = {500: 10, 100: 10}
    with pytest.raises(DenominationDispenseError) as exc:
        DenominationService.calculate_dispense(1250, inventory)
    assert "multiple of 100" in str(exc.value)


def test_dispense_insufficient_inventory():
    inventory = {2000: 1, 500: 0, 200: 0, 100: 1} # total 2100
    with pytest.raises(DenominationDispenseError) as exc:
        DenominationService.calculate_dispense(1500, inventory)
    assert "cannot dispense exact" in str(exc.value)


def test_dispense_zero_or_negative():
    inventory = {500: 10}
    with pytest.raises(DenominationDispenseError):
        DenominationService.calculate_dispense(0, inventory)
    with pytest.raises(DenominationDispenseError):
        DenominationService.calculate_dispense(-500, inventory)
