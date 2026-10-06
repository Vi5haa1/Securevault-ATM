import datetime
from decimal import Decimal
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field

from app.services.iso8583 import Iso8583Message
from app.services.emv import EmvChipSimulator
from app.core.deps import require_permission
from app.db.models.models import User

router = APIRouter(tags=["Security Protocols & Simulation"])


class IsoInspectRequest(BaseModel):
    card_number: str = Field(default="4532015893024826")
    amount: Decimal = Field(default=Decimal("5000.00"))
    atm_code: str = Field(default="SV-ATM-CHE-101")
    stan: str = Field(default="048291")
    tamper_mac: bool = Field(default=False)


class EmvValidateRequest(BaseModel):
    card_pan: str = Field(default="4532015893024826")
    amount: Decimal = Field(default=Decimal("2000.00"))
    atc: int = Field(default=42)
    unpredictable_number: str = Field(default="9B42A1F0")
    arqc: Optional[str] = None
    expiry: str = Field(default="12/28")
    simulate_counter_replay: bool = Field(default=False)


# -------------------------------------------------------------
# Section 11: ISO 8583-Style Protocol Inspector
# -------------------------------------------------------------

@router.post("/transactions/protocol/inspect")
async def inspect_iso8583_message(
    payload: IsoInspectRequest,
    current_user: User = Depends(require_permission("soc:dashboard"))
):
    """
    Simulates transmission of an ISO 8583 financial request (0200),
    verifies its MAC integrity, evaluates security checks, and builds response (0210).
    Never exposes raw unmasked PAN.
    """
    req_msg = Iso8583Message.build_financial_request(
        card_number=payload.card_number,
        amount=payload.amount,
        atm_code=payload.atm_code,
        stan=payload.stan
    )

    if payload.tamper_mac:
        req_msg["mac"] = "BAD0000000000000"
        req_msg["fields"]["DE_064"]["value"] = "BAD0000000000000"

    # Step 1: MAC verification
    mac_valid = Iso8583Message.verify_request_mac(req_msg)

    # Step 2: Response generation
    resp_code = "00" if mac_valid else "91"
    resp_msg = Iso8583Message.build_financial_response(req_msg, response_code=resp_code)

    return {
        "standard": "ISO 8583-STYLE SYNTHETIC FINANCIAL MESSAGE",
        "stages": [
            {"stage": "MESSAGE_INGEST", "status": "COMPLETED", "detail": f"Parsed MTI {req_msg['mti']} ({req_msg['mti_description']})"},
            {"stage": "PAN_MASKING", "status": "COMPLETED", "detail": f"Masked cardholder PAN to {req_msg['fields']['DE_002']['value']}"},
            {"stage": "MAC_VERIFICATION", "status": "PASSED" if mac_valid else "FAILED", "detail": f"DE 64 HMAC-SHA256 check {'VALID' if mac_valid else 'TAMPERED / CORRUPTED'}"},
            {"stage": "AUTHORIZATION", "status": "APPROVED" if mac_valid else "BLOCKED", "detail": f"Generated MTI 0210 with Response Code {resp_code} ({resp_msg['response_description']})"}
        ],
        "request_message": req_msg,
        "response_message": resp_msg,
        "mac_valid": mac_valid
    }


# -------------------------------------------------------------
# Section 12: EMV-Style Card Chip Simulator
# -------------------------------------------------------------

@router.post("/security/cards/validate-chip")
async def validate_emv_chip(
    payload: EmvValidateRequest,
    current_user: User = Depends(require_permission("soc:dashboard"))
):
    """
    Evaluates simulated EMV Smart Card chip security:
    - Application Cryptogram (ARQC) validation
    - Application Transaction Counter (ATC) monotonic & replay checks
    """
    masked_pan = Iso8583Message.mask_pan(payload.card_pan)
    
    # Compute ARQC if not provided
    arqc = payload.arqc
    if not arqc:
        arqc = EmvChipSimulator.generate_arqc(
            card_pan_masked=masked_pan,
            amount=payload.amount,
            atc=payload.atc,
            unpredictable_number=payload.unpredictable_number
        )

    result = EmvChipSimulator.validate_chip_transaction(
        card_pan_masked=masked_pan,
        amount=payload.amount,
        atc=payload.atc,
        arqc=arqc,
        expiry=payload.expiry,
        unpredictable_number=payload.unpredictable_number,
        allow_replay_test=not payload.simulate_counter_replay
    )

    return {
        "standard": "EMV-STYLE SIMULATION",
        "card_pan_masked": masked_pan,
        "atc": payload.atc,
        "unpredictable_number": payload.unpredictable_number,
        "arqc": arqc,
        "result": result
    }


# -------------------------------------------------------------
# Section 13: API Security Center & Inventory
# -------------------------------------------------------------

@router.get("/security/api/inventory")
async def get_api_inventory(
    request: Request,
    current_user: User = Depends(require_permission("soc:dashboard"))
):
    """
    Auto-generates live API inventory mapped against OWASP API Security Top 10.
    Dynamically reflects routes, authentication requirements, rate limits, and risk classifications.
    """
    routes = []
    for route in request.app.routes:
        if hasattr(route, "path") and hasattr(route, "methods"):
            path = route.path
            methods = list(route.methods - {"HEAD", "OPTIONS"})
            if not methods:
                continue

            auth_req = not (path in ["/health", "/docs", "/redoc", "/api/v1/openapi.json"] or path.startswith("/static"))
            
            # Map OWASP category
            owasp_cat = "API1: Broken Object Level Auth" if "accounts" in path or "cards" in path else (
                "API2: Broken Authentication" if "auth" in path else (
                    "API4: Unrestricted Resource Consumption" if "withdraw" in path or "simulations" in path else (
                        "API5: Broken Function Level Auth" if "admin" in path or "rules" in path else "API8: Security Misconfiguration"
                    )
                )
            )

            routes.append({
                "path": path,
                "methods": methods,
                "auth_required": auth_req,
                "owasp_top_10": owasp_cat,
                "rate_limit": "60 req/min" if "withdraw" not in path else "5 req/min",
                "risk_tier": "CRITICAL" if "admin" in path or "withdraw" in path else ("HIGH" if "rules" in path or "keys" in path else "NORMAL")
            })

    return {
        "standard_label": "OWASP API SECURITY TOP 10 INVENTORY",
        "total_endpoints": len(routes),
        "authenticated_endpoints": sum(1 for r in routes if r["auth_required"]),
        "public_endpoints": sum(1 for r in routes if not r["auth_required"]),
        "routes": sorted(routes, key=lambda x: x["path"])
    }
