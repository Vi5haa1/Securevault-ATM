from typing import List, Set, Dict
from fastapi import HTTPException, status
from app.db.models.models import UserRole

# Define fine-grained permission tokens
PERMISSIONS: Dict[str, Set[UserRole]] = {
    # Customer ATM permissions
    "atm:operate": {UserRole.CUSTOMER},
    "account:view_own": {UserRole.CUSTOMER, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "account:transact_own": {UserRole.CUSTOMER},
    
    # ATM Operator permissions
    "atm:view": {UserRole.ATM_OPERATOR, UserRole.BANK_ADMIN, UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN},
    "atm:cash_load": {UserRole.ATM_OPERATOR, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "atm:maintenance": {UserRole.ATM_OPERATOR, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "atm:sensors": {UserRole.ATM_OPERATOR, UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},

    # Security Analyst & SOC permissions
    "soc:dashboard": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "soc:alerts": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "soc:incidents": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "soc:audit_verify": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "soc:tamper_demo": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "soc:simulations": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "risk:view": {UserRole.SECURITY_ANALYST, UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "atm:lockdown": {UserRole.SECURITY_ANALYST, UserRole.SUPER_ADMIN},

    # Bank Admin permissions
    "admin:customers": {UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "admin:atms": {UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "admin:policies": {UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},
    "admin:limits": {UserRole.BANK_ADMIN, UserRole.SUPER_ADMIN},

    # Super Admin only
    "admin:staff": {UserRole.SUPER_ADMIN},
    "admin:security_override": {UserRole.SUPER_ADMIN},
}


def check_role_permission(role: UserRole, permission: str) -> bool:
    """Checks whether the given role holds the required permission."""
    if role == UserRole.SUPER_ADMIN:
        return True
    if role == UserRole.BANK_ADMIN:
        # Bank Admin has full operational access to SOC, simulations, and admin
        if permission.startswith("soc:") or permission.startswith("admin:") or permission.startswith("atm:"):
            return True
    allowed_roles = PERMISSIONS.get(permission, set())
    return role in allowed_roles


def enforce_permission(role: UserRole, permission: str) -> None:
    """Raises HTTP 403 Forbidden if the role does not have the permission."""
    if not check_role_permission(role, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: Role '{role.value}' lacks required permission '{permission}'."
        )
