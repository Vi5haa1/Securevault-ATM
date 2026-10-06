from typing import Optional, Callable
from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.db.models.models import User, UserRole, Account, Customer
from app.core.security import decode_access_token
from app.security.rbac import check_role_permission

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/staff/login", auto_error=False)


async def get_current_user_optional(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Retrieves current user if token is provided and valid, or None."""
    # Check Authorization header if oauth2_scheme didn't catch it
    auth_header = request.headers.get("Authorization")
    if not token and auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]

    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    user_id_str = payload.get("sub")
    if not user_id_str:
        return None

    try:
        user_id = int(user_id_str)
    except ValueError:
        return None

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not user.enabled:
        return None

    return user


async def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """Requires authenticated user or raises HTTP 401."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided or are invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is locked. Please contact security administration."
        )
    return user


def require_permission(permission: str) -> Callable:
    """Dependency factory checking fine-grained role permissions."""
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not check_role_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{current_user.role.value}' lacks permission '{permission}'."
            )
        return current_user
    return permission_checker


def require_roles(*roles: UserRole) -> Callable:
    """Dependency factory checking that user role is among permitted roles."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles and current_user.role != UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Required roles {[r.value for r in roles]}."
            )
        return current_user
    return role_checker


async def verify_account_ownership(
    account_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Account:
    """
    IDOR Protection: Verifies that the authenticated customer owns the given account,
    or is an authorized staff member (SUPER_ADMIN / BANK_ADMIN).
    """
    stmt = select(Account).where(Account.id == account_id)
    result = await db.execute(stmt)
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found.")

    if current_user.role in [UserRole.SUPER_ADMIN, UserRole.BANK_ADMIN]:
        return account

    # For customers, check matching customer_id
    stmt_cust = select(Customer).where(Customer.user_id == current_user.id)
    res_cust = await db.execute(stmt_cust)
    customer = res_cust.scalar_one_or_none()

    if not customer or account.customer_id != customer.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not have ownership of this financial account."
        )

    return account
