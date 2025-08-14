import pytest

from wristband.fastapi_auth.exceptions import InvalidGrantError, WristbandError

########################################
# WRISTBAND ERROR TESTS
########################################


def test_wristband_error_creation_with_description():
    """Test WristbandError creation with both error and description."""
    error = WristbandError("test_error", "This is a test error description")

    assert error.error == "test_error"
    assert error.error_description == "This is a test error description"
    assert str(error) == "test_error: This is a test error description"


def test_wristband_error_creation_without_description():
    """Test WristbandError creation with only error code."""
    error = WristbandError("test_error")

    assert error.error == "test_error"
    assert error.error_description == ""
    assert str(error) == "test_error: "


def test_wristband_error_creation_with_empty_description():
    """Test WristbandError creation with explicitly empty description."""
    error = WristbandError("test_error", "")

    assert error.error == "test_error"
    assert error.error_description == ""
    assert str(error) == "test_error: "


def test_wristband_error_get_error():
    """Test WristbandError.get_error() method."""
    error = WristbandError("unauthorized", "Access denied")

    assert error.get_error() == "unauthorized"


def test_wristband_error_get_error_description():
    """Test WristbandError.get_error_description() method."""
    error = WristbandError("unauthorized", "Access denied")

    assert error.get_error_description() == "Access denied"


def test_wristband_error_get_error_description_empty():
    """Test WristbandError.get_error_description() with empty description."""
    error = WristbandError("unauthorized")

    assert error.get_error_description() == ""


def test_wristband_error_is_exception():
    """Test that WristbandError is an instance of Exception."""
    error = WristbandError("test_error", "description")

    assert isinstance(error, Exception)
    assert isinstance(error, WristbandError)


def test_wristband_error_can_be_raised():
    """Test that WristbandError can be raised and caught."""
    with pytest.raises(WristbandError) as exc_info:
        raise WristbandError("test_error", "Test description")

    assert exc_info.value.error == "test_error"
    assert exc_info.value.error_description == "Test description"


def test_wristband_error_can_be_caught_as_exception():
    """Test that WristbandError can be caught as base Exception."""
    with pytest.raises(Exception) as exc_info:
        raise WristbandError("test_error", "Test description")

    # Should be caught as Exception but still be WristbandError instance
    assert isinstance(exc_info.value, WristbandError)
    assert exc_info.value.error == "test_error"


def test_wristband_error_with_special_characters():
    """Test WristbandError with special characters in messages."""
    error = WristbandError("test_error", "Description with 🔐 emojis and special chars: @#$%")

    assert error.error == "test_error"
    assert error.error_description == "Description with 🔐 emojis and special chars: @#$%"
    assert "🔐" in str(error)


def test_wristband_error_with_multiline_description():
    """Test WristbandError with multiline description."""
    description = "Line 1\nLine 2\nLine 3"
    error = WristbandError("multiline_error", description)

    assert error.error == "multiline_error"
    assert error.error_description == description
    assert "\n" in str(error)


########################################
# INVALID GRANT ERROR TESTS
########################################


def test_invalid_grant_error_creation_with_description():
    """Test InvalidGrantError creation with description."""
    error = InvalidGrantError("Authorization code has expired")

    assert error.error == "invalid_grant"
    assert error.error_description == "Authorization code has expired"
    assert str(error) == "invalid_grant: Authorization code has expired"


def test_invalid_grant_error_creation_without_description():
    """Test InvalidGrantError creation without description."""
    error = InvalidGrantError()

    assert error.error == "invalid_grant"
    assert error.error_description == ""
    assert str(error) == "invalid_grant: "


def test_invalid_grant_error_creation_with_empty_description():
    """Test InvalidGrantError creation with explicitly empty description."""
    error = InvalidGrantError("")

    assert error.error == "invalid_grant"
    assert error.error_description == ""
    assert str(error) == "invalid_grant: "


def test_invalid_grant_error_inherits_from_wristband_error():
    """Test that InvalidGrantError inherits from WristbandError."""
    error = InvalidGrantError("Test description")

    assert isinstance(error, WristbandError)
    assert isinstance(error, InvalidGrantError)
    assert isinstance(error, Exception)


def test_invalid_grant_error_get_error():
    """Test InvalidGrantError.get_error() method."""
    error = InvalidGrantError("Token expired")

    assert error.get_error() == "invalid_grant"


def test_invalid_grant_error_get_error_description():
    """Test InvalidGrantError.get_error_description() method."""
    error = InvalidGrantError("Refresh token has been revoked")

    assert error.get_error_description() == "Refresh token has been revoked"


def test_invalid_grant_error_can_be_raised():
    """Test that InvalidGrantError can be raised and caught."""
    with pytest.raises(InvalidGrantError) as exc_info:
        raise InvalidGrantError("Authorization code already used")

    assert exc_info.value.error == "invalid_grant"
    assert exc_info.value.error_description == "Authorization code already used"


def test_invalid_grant_error_can_be_caught_as_wristband_error():
    """Test that InvalidGrantError can be caught as WristbandError."""
    with pytest.raises(WristbandError) as exc_info:
        raise InvalidGrantError("Test description")

    # Should be caught as WristbandError but still be InvalidGrantError instance
    assert isinstance(exc_info.value, InvalidGrantError)
    assert exc_info.value.error == "invalid_grant"


def test_invalid_grant_error_can_be_caught_as_exception():
    """Test that InvalidGrantError can be caught as base Exception."""
    with pytest.raises(Exception) as exc_info:
        raise InvalidGrantError("Test description")

    # Should be caught as Exception but still be InvalidGrantError instance
    assert isinstance(exc_info.value, InvalidGrantError)
    assert exc_info.value.error == "invalid_grant"


########################################
# INTEGRATION TESTS
########################################


def test_exception_hierarchy():
    """Test the complete exception hierarchy."""
    error = InvalidGrantError("Test")

    # Test isinstance checks
    assert isinstance(error, Exception)
    assert isinstance(error, WristbandError)
    assert isinstance(error, InvalidGrantError)

    # Test that it's not other exception types
    assert not isinstance(error, ValueError)
    assert not isinstance(error, TypeError)


def test_multiple_exception_handling():
    """Test handling multiple different error types."""
    errors = [
        WristbandError("custom_error", "Custom error message"),
        InvalidGrantError("Grant expired"),
        WristbandError("another_error"),
        InvalidGrantError(),
    ]

    for error in errors:
        assert isinstance(error, WristbandError)
        assert isinstance(error, Exception)
        assert hasattr(error, "error")
        assert hasattr(error, "error_description")
        assert callable(error.get_error)
        assert callable(error.get_error_description)


def test_error_message_formatting():
    """Test that error messages are formatted consistently."""
    test_cases = [
        ("error1", "description1", "error1: description1"),
        ("error2", "", "error2: "),
        ("error_with_spaces", "description with spaces", "error_with_spaces: description with spaces"),
        ("", "description_only", ": description_only"),
        ("", "", ": "),
    ]

    for error_code, description, expected_str in test_cases:
        error = WristbandError(error_code, description)
        assert str(error) == expected_str


def test_oauth_error_scenarios():
    """Test common OAuth error scenarios using InvalidGrantError."""
    scenarios = [
        "Authorization code has expired",
        "Authorization code already used",
        "Invalid authorization code",
        "Refresh token expired",
        "Refresh token revoked",
        "",  # No description
    ]

    for description in scenarios:
        error = InvalidGrantError(description)
        assert error.error == "invalid_grant"
        assert error.error_description == description
        assert error.get_error() == "invalid_grant"
        assert error.get_error_description() == description


def test_error_attributes_immutability():
    """Test that error attributes can be accessed but the class works as expected."""
    error = WristbandError("test_error", "test_description")

    # Test that attributes are accessible
    assert error.error == "test_error"
    assert error.error_description == "test_description"

    # Test that methods return the same values
    assert error.get_error() == error.error
    assert error.get_error_description() == error.error_description


def test_error_str_representation_consistency():
    """Test that string representation is consistent."""
    error1 = WristbandError("test", "description")
    error2 = InvalidGrantError("description")

    # Test WristbandError str representation
    assert str(error1) == "test: description"

    # Test InvalidGrantError str representation
    assert str(error2) == "invalid_grant: description"

    # Test that the format is consistent
    assert ": " in str(error1)
    assert ": " in str(error2)
