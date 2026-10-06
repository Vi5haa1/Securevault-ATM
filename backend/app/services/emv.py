import hashlib
import hmac
import datetime
from typing import Dict, Any, Optional, Tuple
from decimal import Decimal

# In-memory Application Transaction Counter (ATC) replay tracker for demo cards
_USED_ATC_STORE: set[Tuple[str, int]] = set()

class EmvChipSimulator:
    """
    EMV-Style Integrated Circuit (IC) Chip Security Simulator.
    Simulates:
    - Application Transaction Counter (ATC)
    - Application Cryptogram (ARQC - Authorization Request Cryptogram / TC - Transaction Certificate)
    - Cryptogram Replay Detection
    - Chip Expiry & Application Status Validation
    Labeled: EMV-STYLE SIMULATION (Educational / Simulated Control Mapping)
    """

    @classmethod
    def generate_arqc(
        cls,
        card_pan_masked: str,
        amount: Decimal,
        atc: int,
        unpredictable_number: str,
        card_session_key: bytes = b"emv-card-derived-key-secret-32b"
    ) -> str:
        """
        Generates simulated ARQC (Authorization Request Cryptogram) using HMAC-SHA256
        over (PAN, Amount, ATC, Unpredictable Number).
        """
        data = f"{card_pan_masked}|{amount}|{atc}|{unpredictable_number}"
        arqc = hmac.new(card_session_key, data.encode("utf-8"), hashlib.sha256).hexdigest()[:16].upper()
        return arqc

    @classmethod
    def validate_chip_transaction(
        cls,
        card_pan_masked: str,
        amount: Decimal,
        atc: int,
        arqc: str,
        expiry: str,  # MM/YY
        unpredictable_number: str,
        allow_replay_test: bool = False
    ) -> Dict[str, Any]:
        """
        Validates the simulated EMV chip parameters:
        1. Expiry check
        2. Application Transaction Counter (ATC) monotonic & replay check
        3. Cryptogram (ARQC) verification
        """
        # 1. Expiry Check
        try:
            exp_m, exp_y = int(expiry[:2]), int(f"20{expiry[3:]}")
            now = datetime.datetime.now(datetime.timezone.utc)
            if (exp_y < now.year) or (exp_y == now.year and exp_m < now.month):
                return {
                    "valid": False,
                    "rejection_reason": "CARD_EXPIRED",
                    "status_description": f"Chip application expired on {expiry}",
                    "standard_label": "EMV-STYLE SIMULATION"
                }
        except Exception:
            pass

        # 2. ATC Replay Check
        replay_key = (card_pan_masked, atc)
        if not allow_replay_test and replay_key in _USED_ATC_STORE:
            return {
                "valid": False,
                "rejection_reason": "CRYPTOGRAM_REPLAY_DETECTED",
                "status_description": f"Application Transaction Counter (ATC #{atc}) was already consumed! Replay attack detected.",
                "standard_label": "EMV-STYLE SIMULATION"
            }

        # 3. Cryptogram Verification
        expected_arqc = cls.generate_arqc(card_pan_masked, amount, atc, unpredictable_number)
        if not hmac.compare_digest(arqc.upper(), expected_arqc):
            return {
                "valid": False,
                "rejection_reason": "INVALID_APPLICATION_CRYPTOGRAM",
                "status_description": "Cryptographic ARQC checksum mismatch. Suspected counterfeit chip clone.",
                "standard_label": "EMV-STYLE SIMULATION"
            }

        # Record consumed ATC
        _USED_ATC_STORE.add(replay_key)

        return {
            "valid": True,
            "rejection_reason": None,
            "status_description": f"EMV Chip Verified Successfully. ARQC validated for ATC #{atc}.",
            "atc": atc,
            "arqc": arqc,
            "card_status": "AUTHENTICATED",
            "standard_label": "EMV-STYLE SIMULATION"
        }

    @classmethod
    def reset_atc_cache(cls):
        """Cleans consumed ATC replay cache for demo repeatability."""
        _USED_ATC_STORE.clear()
