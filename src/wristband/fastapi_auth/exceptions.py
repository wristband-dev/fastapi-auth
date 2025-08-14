class WristbandError(Exception):
    """
    Base exception class for all Wristband-related errors.

    This exception captures both an error code and an optional error description,
    providing structured error handling for the Wristband SDK.

    Attributes:
        error (str): The error code or type identifier.
        error_description (str): Optional detailed description of the error.
    """

    def __init__(self, error: str, error_description: str = "") -> None:
        """
        Initialize a WristbandError with an error code and optional description.

        Args:
            error: The error code or type (e.g., "invalid_grant", "unauthorized").
            error_description: Optional detailed description of what went wrong.
        """
        super().__init__(f"{error}: {error_description}")
        self.error = error
        self.error_description = error_description

    def get_error(self) -> str:
        """
        Get the error code.

        Returns:
            The error code string.
        """
        return self.error

    def get_error_description(self) -> str:
        """
        Get the error description.

        Returns:
            The error description string (may be empty).
        """
        return self.error_description


class InvalidGrantError(WristbandError):
    """
    Exception raised when an OAuth grant is invalid or expired.

    This typically occurs during token exchange operations when:
    - Authorization code has expired
    - Authorization code has already been used
    - Authorization code is malformed
    - Refresh token has expired or been revoked

    This is a specialized WristbandError that automatically sets the error type
    to "invalid_grant" as defined in OAuth 2.0 specifications.
    """

    def __init__(self, error_description: str = "") -> None:
        """
        Initialize an InvalidGrantError with an optional description.

        Args:
            error_description: Optional detailed description of why the grant is invalid.
        """
        super().__init__("invalid_grant", error_description)
