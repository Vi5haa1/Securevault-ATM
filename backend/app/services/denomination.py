from typing import List, Dict, Optional, Tuple
from decimal import Decimal


class DenominationDispenseError(Exception):
    pass


class DenominationService:
    SUPPORTED_DENOMINATIONS = [2000, 500, 200, 100]

    @classmethod
    def calculate_dispense(
        cls,
        requested_amount: int,
        available_inventory: Dict[int, int]
    ) -> List[Dict[str, int]]:
        """
        Greedy denomination dispensing algorithm with inventory constraint verification.
        Args:
            requested_amount: Total cash requested in INR (must be multiple of 100).
            available_inventory: Mapping of denomination -> available note count.
        Returns:
            List of dicts: [{"denomination": 500, "count": 4}, ...]
        Raises:
            DenominationDispenseError: If amount is invalid or cannot be fulfilled exactly.
        """
        if requested_amount <= 0:
            raise DenominationDispenseError("Withdrawal amount must be strictly greater than 0.")

        if requested_amount % 100 != 0:
            raise DenominationDispenseError("Withdrawal amount must be a multiple of 100.")

        remaining = requested_amount
        dispensed: List[Dict[str, int]] = []

        # Sort descending
        for denom in sorted(cls.SUPPORTED_DENOMINATIONS, reverse=True):
            available_count = available_inventory.get(denom, 0)
            if available_count <= 0:
                continue

            needed_count = remaining // denom
            notes_to_give = min(needed_count, available_count)

            if notes_to_give > 0:
                dispensed.append({
                    "denomination": denom,
                    "count": notes_to_give
                })
                remaining -= notes_to_give * denom

        if remaining != 0:
            raise DenominationDispenseError(
                f"ATM cannot dispense exact requested amount of INR {requested_amount} with current note inventory."
            )

        return dispensed
