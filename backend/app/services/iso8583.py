import datetime
import hashlib
import hmac
from typing import Dict, Any, Optional, Tuple
from decimal import Decimal

class Iso8583Message:
    """
    Synthetic ISO 8583-Style Payment Message Parser & Builder.
    Educational simulation for financial message transmission and MAC verification.
    NEVER logs or exposes unmasked Primary Account Numbers (PAN).
    """

    @classmethod
    def mask_pan(cls, pan: str) -> str:
        """Masks PAN: keeps first 6 and last 4 digits (PCI DSS compliant format)."""
        clean = "".join(filter(str.isdigit, pan))
        if len(clean) < 10:
            return "******"
        return f"{clean[:6]}{'*' * (len(clean) - 10)}{clean[-4:]}"

    @classmethod
    def build_financial_request(
        cls,
        card_number: str,
        amount: Decimal,
        atm_code: str,
        stan: str,
        processing_code: str = "010000",
        mac_key: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Builds a synthetic ISO 8583 0200 Financial Transaction Request message.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        de7_transmission_dt = now.strftime("%m%d%H%M%S")
        
        # Amount in minor units (12 digits, zero-padded)
        minor_units = int(amount * 100)
        de4_amount = f"{minor_units:012d}"
        
        masked_pan = cls.mask_pan(card_number)

        # Canonical message payload for MAC calculation
        canonical_str = f"0200|{masked_pan}|{processing_code}|{de4_amount}|{de7_transmission_dt}|{stan}|{atm_code}|356"
        key = mac_key or b"securevault-synthetic-mac-key-32b"
        mac = hmac.new(key, canonical_str.encode("utf-8"), hashlib.sha256).hexdigest()[:16].upper()

        return {
            "mti": "0200",
            "mti_description": "Financial Transaction Request",
            "fields": {
                "DE_002": {"name": "Primary Account Number (PAN)", "value": masked_pan, "tooltip": "Cardholder PAN with PCI DSS masking (first 6, last 4)"},
                "DE_003": {"name": "Processing Code", "value": processing_code, "tooltip": "010000 = Cash Withdrawal from Primary Savings/Current"},
                "DE_004": {"name": "Amount, Transaction", "value": de4_amount, "tooltip": f"Minor currency units (12 digits): INR {amount:,.2f}"},
                "DE_007": {"name": "Transmission Date & Time", "value": de7_transmission_dt, "tooltip": "UTC timestamp in MMDDhhmmss format"},
                "DE_011": {"name": "Systems Trace Audit Number (STAN)", "value": stan, "tooltip": "Unique 6-digit transaction trace sequence number"},
                "DE_041": {"name": "Card Acceptor Terminal ID", "value": atm_code, "tooltip": "Unique physical identifier of the ATM terminal"},
                "DE_049": {"name": "Currency Code, Transaction", "value": "356", "tooltip": "ISO 4217 code 356 = Indian Rupee (INR)"},
                "DE_064": {"name": "Message Authentication Code (MAC)", "value": mac, "tooltip": "HMAC-SHA256 integrity block verifying message authenticity"}
            },
            "canonical_payload": canonical_str,
            "mac": mac,
            "timestamp": now.isoformat(),
            "standard_label": "ISO 8583-STYLE SYNTHETIC MESSAGE"
        }

    @classmethod
    def build_financial_response(
        cls,
        request_msg: Dict[str, Any],
        response_code: str = "00",  # 00 = Approved, 51 = Insufficient Funds, 05 = Do Not Honor
        auth_code: Optional[str] = "SV9982"
    ) -> Dict[str, Any]:
        """
        Builds a synthetic ISO 8583 0210 Financial Transaction Response message.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        req_fields = request_msg.get("fields", {})

        response_descriptions = {
            "00": "Approved / Completed Successfully",
            "05": "Do Not Honor (Zero-Trust Security Block)",
            "51": "Insufficient Funds",
            "55": "Incorrect PIN / Authentication Failure",
            "75": "Allowable PIN Tries Exceeded (Card Locked)",
            "91": "Card Issuer or Cryptographic Vault Inoperative"
        }

        return {
            "mti": "0210",
            "mti_description": "Financial Transaction Response",
            "response_code": response_code,
            "response_description": response_descriptions.get(response_code, "Transaction Declined"),
            "fields": {
                "DE_002": req_fields.get("DE_002", {}),
                "DE_003": req_fields.get("DE_003", {}),
                "DE_004": req_fields.get("DE_004", {}),
                "DE_007": {"name": "Transmission Date & Time", "value": now.strftime("%m%d%H%M%S"), "tooltip": "Response transmission timestamp"},
                "DE_011": req_fields.get("DE_011", {}),
                "DE_038": {"name": "Authorization Identification Response", "value": auth_code or "N/A", "tooltip": "Core banking approval authorization code"},
                "DE_039": {"name": "Response Code", "value": response_code, "tooltip": f"Action code: {response_descriptions.get(response_code, 'Declined')}"},
                "DE_041": req_fields.get("DE_041", {}),
                "DE_049": req_fields.get("DE_049", {})
            },
            "timestamp": now.isoformat(),
            "standard_label": "ISO 8583-STYLE SYNTHETIC MESSAGE"
        }

    @classmethod
    def verify_request_mac(cls, request_msg: Dict[str, Any], mac_key: Optional[bytes] = None) -> bool:
        """Verifies MAC integrity of an incoming ISO 8583 request message."""
        canonical = request_msg.get("canonical_payload", "")
        received_mac = request_msg.get("mac", "")
        key = mac_key or b"securevault-synthetic-mac-key-32b"
        expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()[:16].upper()
        return hmac.compare_digest(received_mac, expected)
