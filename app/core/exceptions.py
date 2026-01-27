"""
Custom Exceptions
Domain and application-level exceptions.
"""
from fastapi import HTTPException, status


class AuthenticationError(HTTPException):
    """Authentication failed."""

    def __init__(self, detail: str = "Invalid credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """Authorization failed."""

    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class NotFoundError(HTTPException):
    """Resource not found."""

    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )


class ValidationError(HTTPException):
    """Validation failed."""

    def __init__(self, detail: str = "Validation failed"):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
        )


class AccountLockedError(HTTPException):
    """Account is locked."""

    def __init__(self, detail: str = "Account is locked"):
        super().__init__(
            status_code=status.HTTP_423_LOCKED,
            detail=detail,
        )


class MFARequiredError(HTTPException):
    """MFA verification required."""

    def __init__(self, detail: str = "MFA verification required"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )


class MFAVerificationError(HTTPException):
    """MFA verification failed."""

    def __init__(self, detail: str = "Invalid MFA code"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )
