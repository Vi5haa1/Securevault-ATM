import re
from typing import Tuple, List


class PinPolicyError(Exception):
    pass


class PinPolicyService:
    # Common known weak PINs
    WEAK_PINS = {
        "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
        "1234", "4321", "1212", "6969", "2580", "1357", "2468", "0852",
        "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
        "123456", "654321"
    }

    @classmethod
    def validate_pin(cls, pin: str, min_len: int = 4, max_len: int = 6) -> Tuple[bool, List[str]]:
        """
        Validates an ATM PIN against security rules:
        - 4-6 digits strictly
        - Only numeric characters
        - Not in weak PIN dictionary
        - No all-identical digits
        - No ascending or descending sequences
        - No recent year patterns (1920-2030)
        """
        errors = []
        if not pin or not pin.isdigit():
            errors.append("PIN must contain only digits.")
            return False, errors

        if len(pin) < min_len or len(pin) > max_len:
            errors.append(f"PIN must be between {min_len} and {max_len} digits long.")

        if pin in cls.WEAK_PINS:
            errors.append("PIN is too common or easily guessable.")

        # Check all identical digits
        if len(set(pin)) == 1:
            errors.append("PIN cannot consist of identical digits.")

        # Check ascending sequences (e.g. 1234, 4567)
        is_ascending = True
        is_descending = True
        for i in range(len(pin) - 1):
            if int(pin[i+1]) != int(pin[i]) + 1:
                is_ascending = False
            if int(pin[i+1]) != int(pin[i]) - 1:
                is_descending = False

        if is_ascending:
            errors.append("PIN cannot be an ascending sequence.")
        if is_descending:
            errors.append("PIN cannot be a descending sequence.")

        # Check if 4 digits resemble a year between 1920 and 2030
        if len(pin) == 4:
            year_val = int(pin)
            if 1920 <= year_val <= 2030:
                errors.append("PIN cannot be a recent calendar year.")

        return len(errors) == 0, errors
