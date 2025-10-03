import pytest

from wristband.fastapi_auth import CallbackData, UserInfo
from wristband.fastapi_auth.session import Session
from wristband.fastapi_auth.utils import DataEncryptor


# Fixtures
@pytest.fixture
def secret_key():
    return "a" * 32


@pytest.fixture
def encryptor(secret_key):
    return DataEncryptor(secret_key)


@pytest.fixture
def session(encryptor):
    """Create a Session instance for testing"""
    return Session(
        encryptor=encryptor,
        session_cookie_name="session",
        session_cookie_domain=None,
        csrf_cookie_name="CSRF-TOKEN",
        csrf_cookie_domain=None,
        max_age=3600,
        path="/",
        same_site="lax",
        secure=True,
    )


class TestSessionDataAccess:
    """Test getting and setting session data through dict-like interface"""

    # Attribute-style access
    def test_getattr_returns_value(self, session):
        session._data["user_id"] = "test_user"

        assert session.user_id == "test_user"

    def test_getattr_returns_none_for_missing_key(self, session):
        assert session.nonexistent_key is None

    def test_setattr_sets_value(self, session):
        session.user_id = "test_user"

        assert session._data["user_id"] == "test_user"

    def test_setattr_validates_json_serializable(self, session):
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session.invalid_func = lambda x: x

    # Dict-style access
    def test_getitem_returns_value(self, session):
        session._data["user_id"] = "test_user"

        assert session["user_id"] == "test_user"

    def test_getitem_raises_keyerror_for_missing(self, session):
        with pytest.raises(KeyError):
            _ = session["nonexistent"]

    def test_setitem_sets_value(self, session):
        session["user_id"] = "test_user"

        assert session._data["user_id"] == "test_user"

    def test_setitem_validates_json_serializable(self, session):
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session["invalid"] = lambda x: x

    def test_setitem_accepts_various_types(self, session):
        session["string"] = "value"
        session["number"] = 42
        session["float"] = 3.14
        session["bool"] = True
        session["none"] = None
        session["list"] = [1, 2, 3]
        session["dict"] = {"nested": "data"}

        assert session["string"] == "value"
        assert session["number"] == 42
        assert session["float"] == 3.14
        assert session["bool"] is True
        assert session["none"] is None
        assert session["list"] == [1, 2, 3]
        assert session["dict"] == {"nested": "data"}

    def test_delitem_removes_key(self, session):
        session["user_id"] = "test_user"

        del session["user_id"]

        assert "user_id" not in session._data

    def test_delitem_raises_keyerror_for_missing(self, session):
        with pytest.raises(KeyError):
            del session["nonexistent"]

    # Dict-like methods
    def test_contains_returns_true_when_key_exists(self, session):
        session["user_id"] = "test_user"

        assert "user_id" in session

    def test_contains_returns_false_when_key_missing(self, session):
        assert "nonexistent" not in session

    def test_len_returns_number_of_items(self, session):
        assert len(session) == 0

        session["key1"] = "value1"
        assert len(session) == 1

        session["key2"] = "value2"
        assert len(session) == 2

        del session["key1"]
        assert len(session) == 1

    def test_iter_iterates_over_keys(self, session):
        session["key1"] = "value1"
        session["key2"] = "value2"
        session["key3"] = "value3"

        keys = list(session)

        assert set(keys) == {"key1", "key2", "key3"}

    def test_get_with_default(self, session):
        result = session.get("nonexistent", "default_value")

        assert result == "default_value"

    def test_get_without_default(self, session):
        result = session.get("nonexistent")

        assert result is None

    def test_get_returns_existing_value(self, session):
        session["user_id"] = "test_user"

        result = session.get("user_id")

        assert result == "test_user"

    def test_get_ignores_default_when_key_exists(self, session):
        session["user_id"] = "test_user"

        result = session.get("user_id", "default")

        assert result == "test_user"

    def test_to_dict_returns_copy(self, session):
        session["user_id"] = "test_user"
        session["is_authenticated"] = True

        result = session.to_dict()

        assert result == {"user_id": "test_user", "is_authenticated": True}
        assert result is not session._data  # Should be a copy

    def test_to_dict_modifications_dont_affect_session(self, session):
        session["user_id"] = "test_user"

        result = session.to_dict()
        result["user_id"] = "modified"

        assert session["user_id"] == "test_user"

    def test_to_dict_shallow_copy_behavior(self, session):
        """Test that to_dict() returns shallow copy - nested mutable objects remain references"""
        session["nested"] = {"inner": ["list"]}

        result = session.to_dict()

        # Modifying the dict itself doesn't affect session (new dict)
        result["new_key"] = "new_value"
        assert "new_key" not in session

        # But nested mutable objects are still references
        result["nested"]["inner"].append("modified")
        assert session["nested"]["inner"] == ["list", "modified"]

    def test_mixed_access_methods(self, session):
        """Test that different access methods all work on the same data"""
        session.user_id = "attr_style"
        assert session["user_id"] == "attr_style"
        assert session.get("user_id") == "attr_style"

        session["email"] = "dict_style@example.com"
        assert session.email == "dict_style@example.com"
        assert session.get("email") == "dict_style@example.com"

    def test_empty_session_behavior(self, session):
        """Test behavior of empty session"""
        assert len(session) == 0
        assert list(session) == []
        assert session.to_dict() == {}
        assert session.get("anything") is None
        assert "anything" not in session


class TestSessionFromCallback:
    """Test creating session from auth callback"""

    @pytest.fixture
    def callback_data(self):
        """Standard callback data fixture"""
        return CallbackData(
            access_token="access_token_123",
            id_token="id_token_123",
            expires_at=1234567890000,
            expires_in=3600,
            tenant_name="test-tenant",
            user_info=UserInfo(
                user_id="user_123",
                tenant_id="tenant_123",
                application_id="app_123",
                identity_provider_name="Wristband",
                email="test@example.com",
            ),
            custom_state={"key": "value"},
            refresh_token="refresh_token_123",
            return_url="/dashboard",
            tenant_custom_domain="custom.example.com",
        )

    @pytest.fixture
    def minimal_callback_data(self):
        """CallbackData with only required fields"""
        return CallbackData(
            access_token="token",
            id_token="id_token",
            expires_at=1234567890000,
            expires_in=3600,
            tenant_name="tenant",
            user_info=UserInfo(
                user_id="user_id",
                tenant_id="tenant_id",
                application_id="app_id",
                identity_provider_name="Wristband",
            ),
            custom_state=None,
            refresh_token=None,
            return_url=None,
            tenant_custom_domain=None,
        )

    def test_from_callback_with_valid_data(self, session, callback_data):
        session.from_callback(callback_data)

        assert session["is_authenticated"] is True
        assert session["access_token"] == "access_token_123"
        assert session["expires_at"] == 1234567890000
        assert session["user_id"] == "user_123"
        assert session["tenant_id"] == "tenant_123"
        assert session["tenant_name"] == "test-tenant"
        assert session["refresh_token"] == "refresh_token_123"
        assert session["tenant_custom_domain"] == "custom.example.com"
        assert "csrf_token" in session
        assert len(session["csrf_token"]) > 0

    def test_from_callback_with_minimal_data(self, session, minimal_callback_data):
        """Test with only required fields - optional fields are None"""
        session.from_callback(minimal_callback_data)

        assert session["is_authenticated"] is True
        assert session["access_token"] == "token"
        assert session["user_id"] == "user_id"
        assert session["tenant_id"] == "tenant_id"
        assert session["tenant_name"] == "tenant"
        # Optional fields should not be in session dict when None
        assert "refresh_token" not in session._data
        assert "tenant_custom_domain" not in session._data

    def test_from_callback_with_custom_fields(self, session, callback_data):
        custom_fields = {"role": "admin", "preferences": {"theme": "dark"}}

        session.from_callback(callback_data, custom_fields)

        assert session["role"] == "admin"
        assert session["preferences"]["theme"] == "dark"
        # Core fields still present
        assert session["is_authenticated"] is True
        assert session["user_id"] == "user_123"

    def test_from_callback_with_empty_custom_fields(self, session, callback_data):
        """Test with empty dict for custom_fields"""
        session.from_callback(callback_data, custom_fields={})

        assert session["is_authenticated"] is True
        assert session["user_id"] == "user_123"

    def test_from_callback_with_unicode_custom_fields(self, session, callback_data):
        """Test custom fields with unicode characters"""
        custom_fields = {
            "name": "José García",
            "city": "São Paulo",
            "emoji": "🎉",
            "chinese": "你好",
        }

        session.from_callback(callback_data, custom_fields)

        assert session["name"] == "José García"
        assert session["emoji"] == "🎉"
        assert session["chinese"] == "你好"

    def test_from_callback_with_nested_custom_fields(self, session, callback_data):
        """Test with deeply nested structures"""
        custom_fields = {"level1": {"level2": {"level3": {"level4": {"value": "deep"}}}}}

        session.from_callback(callback_data, custom_fields)

        assert session["level1"]["level2"]["level3"]["level4"]["value"] == "deep"

    def test_from_callback_with_list_custom_fields(self, session, callback_data):
        """Test custom fields containing lists"""
        custom_fields = {
            "roles": ["admin", "user", "moderator"],
            "permissions": [{"resource": "api", "action": "read"}],
        }

        session.from_callback(callback_data, custom_fields)

        assert session["roles"] == ["admin", "user", "moderator"]
        assert len(session["permissions"]) == 1

    def test_from_callback_generates_csrf_token(self, session, callback_data):
        session.from_callback(callback_data)

        assert "csrf_token" in session
        csrf_token = session["csrf_token"]
        assert isinstance(csrf_token, str)
        assert len(csrf_token) == 32  # Token is 32 hex characters
        # Verify it's valid hex
        int(csrf_token, 16)

    def test_from_callback_generates_unique_csrf_tokens(self, session, callback_data):
        """Test that each call generates a unique CSRF token"""
        session.from_callback(callback_data)
        csrf1 = session["csrf_token"]

        # Create new session and generate again
        session.from_callback(callback_data)
        csrf2 = session["csrf_token"]

        assert csrf1 != csrf2

    def test_from_callback_raises_when_callback_data_none(self, session):
        with pytest.raises(ValueError, match="callback_data is required"):
            session.from_callback(None)

    def test_from_callback_raises_when_user_info_missing(self, session, callback_data):
        callback_data.user_info = None

        with pytest.raises(ValueError, match="user_info is required"):
            session.from_callback(callback_data)

    def test_from_callback_raises_when_custom_fields_not_serializable(self, session, callback_data):
        custom_fields = {"func": lambda x: x}

        with pytest.raises(ValueError, match="must be JSON serializable"):
            session.from_callback(callback_data, custom_fields)

    def test_from_callback_raises_with_non_serializable_nested_data(self, session, callback_data):
        """Test with non-serializable data nested deeply"""
        custom_fields = {"data": {"nested": {"func": lambda: None}}}

        with pytest.raises(ValueError, match="must be JSON serializable"):
            session.from_callback(callback_data, custom_fields)

    def test_from_callback_sets_needs_save_flag(self, session, callback_data):
        assert session._needs_save is False

        session.from_callback(callback_data)

        assert session._needs_save is True

    def test_from_callback_overwrites_existing_session(self, session, callback_data):
        """Test that from_callback replaces any existing session data"""
        session["old_key"] = "old_value"
        session["user_id"] = "old_user"

        session.from_callback(callback_data)

        assert "old_key" not in session._data
        assert session["user_id"] == "user_123"  # New value from callback

    def test_from_callback_includes_only_non_none_optional_fields(self, session, callback_data):
        """Verify optional fields are excluded when None"""
        # Set one optional field to None
        callback_data.refresh_token = None

        session.from_callback(callback_data)

        assert "refresh_token" not in session._data
        assert "tenant_custom_domain" in session._data  # This one is not None

    def test_from_callback_with_all_optional_fields_none(self, session, minimal_callback_data):
        """Test when all optional fields are None"""
        session.from_callback(minimal_callback_data)

        # Core fields should be present
        assert "is_authenticated" in session._data
        assert "access_token" in session._data
        assert "user_id" in session._data
        assert "csrf_token" in session._data

        # Optional fields should not be present
        assert "refresh_token" not in session._data
        assert "tenant_custom_domain" not in session._data

    def test_from_callback_custom_fields_override_collision(self, session, callback_data):
        """Test that custom fields can override callback fields"""
        custom_fields = {"user_id": "custom_override"}

        session.from_callback(callback_data, custom_fields)

        # Custom field should win since dict.update() is called after
        assert session["user_id"] == "custom_override"


class TestSessionSaveAndClear:
    """Test save() and clear() methods"""

    def test_save_sets_needs_save_flag(self, session):
        assert session._needs_save is False

        session.save()

        assert session._needs_save is True

    def test_save_can_be_called_multiple_times(self, session):
        session.save()
        assert session._needs_save is True

        session.save()
        assert session._needs_save is True  # Still true

    def test_save_does_not_modify_data(self, session):
        """Test that save() only sets flag, doesn't change data"""
        session["user_id"] = "test_user"
        original_data = session.to_dict()

        session.save()

        assert session.to_dict() == original_data

    def test_clear_empties_data(self, session):
        session["user_id"] = "test_user"
        session["is_authenticated"] = True
        session["access_token"] = "token"

        session.clear()

        assert len(session) == 0
        assert session.to_dict() == {}

    def test_clear_sets_needs_clear_flag(self, session):
        assert session._needs_clear is False

        session.clear()

        assert session._needs_clear is True

    def test_clear_unsets_needs_save_flag(self, session):
        session.save()
        assert session._needs_save is True

        session.clear()

        assert session._needs_save is False
        assert session._needs_clear is True

    def test_clear_after_save(self, session):
        """Test that clear takes precedence over save"""
        session["user_id"] = "test_user"
        session.save()

        session.clear()

        assert session._needs_clear is True
        assert session._needs_save is False
        assert len(session) == 0

    def test_save_after_clear(self, session):
        """Test save after clear (unusual but valid)"""
        session["user_id"] = "test_user"
        session.clear()
        assert session._needs_clear is True

        # Add new data and save
        session["new_user"] = "new"
        session.save()

        # save() doesn't reset _needs_clear, so both flags could be true
        # but clear takes precedence in _persist()
        assert session._needs_clear is True
        assert session["new_user"] == "new"

    def test_clear_on_empty_session(self, session):
        """Test clearing when session is already empty"""
        session.clear()

        assert len(session) == 0
        assert session._needs_clear is True

    def test_clear_multiple_times(self, session):
        session["user_id"] = "test"

        session.clear()
        assert session._needs_clear is True
        assert len(session) == 0

        session.clear()
        assert session._needs_clear is True
        assert len(session) == 0

    def test_save_does_not_affect_clear_flag(self, session):
        """Test that save() doesn't change _needs_clear when set by clear()"""
        session["user_id"] = "test"
        session.clear()  # This sets _needs_clear = True internally

        # Verify clear flag is set
        assert session._needs_clear is True

        # Now call save
        session.save()

        # save() only sets _needs_save, doesn't touch _needs_clear
        assert session._needs_clear is True
        assert session._needs_save is True

    def test_session_state_after_clear(self, session):
        """Verify all state is reset after clear"""
        session["user_id"] = "user"
        session["is_authenticated"] = True
        session["nested"] = {"key": "value"}

        session.clear()

        assert "user_id" not in session
        assert "is_authenticated" not in session
        assert "nested" not in session
        assert list(session) == []


class TestSessionValidation:
    """Test data validation and serialization"""

    def test_setitem_rejects_non_serializable_function(self, session):
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session["func"] = lambda x: x

    def test_setitem_rejects_non_serializable_object(self, session):
        class NonSerializable:
            pass

        with pytest.raises(ValueError, match="must be JSON serializable"):
            session["obj"] = NonSerializable()

    def test_setattr_rejects_non_serializable_via_setitem(self, session):
        """Test that __setattr__ uses __setitem__ validation"""
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session.func = lambda x: x

    def test_setitem_rejects_non_serializable_nested_in_dict(self, session):
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session["data"] = {"nested": {"func": lambda: None}}

    def test_setitem_rejects_non_serializable_nested_in_list(self, session):
        with pytest.raises(ValueError, match="must be JSON serializable"):
            session["data"] = [1, 2, lambda: None]

    def test_accepts_serializable_nested_structures(self, session):
        complex_data = {
            "level1": {
                "level2": {
                    "strings": ["a", "b", "c"],
                    "numbers": [1, 2, 3],
                    "nested": {
                        "bool": True,
                        "none": None,
                    },
                }
            }
        }

        session["complex"] = complex_data

        assert session["complex"]["level1"]["level2"]["strings"] == ["a", "b", "c"]

    def test_accepts_unicode_characters(self, session):
        session["name"] = "José García"
        session["city"] = "São Paulo"
        session["emoji"] = "🎉"
        session["chinese"] = "你好"
        session["arabic"] = "مرحبا"

        assert session["name"] == "José García"
        assert session["emoji"] == "🎉"
        assert session["chinese"] == "你好"

    def test_accepts_special_characters(self, session):
        session["path"] = "/api/v1/users"
        session["query"] = "name=John&age=30"
        session["special"] = "!@#$%^&*()"
        session["quotes"] = 'He said "hello"'

        assert session["special"] == "!@#$%^&*()"
        assert session["quotes"] == 'He said "hello"'

    def test_accepts_empty_strings(self, session):
        session["empty"] = ""

        assert session["empty"] == ""

    def test_accepts_whitespace_strings(self, session):
        session["spaces"] = "   "
        session["tabs"] = "\t\t"
        session["newlines"] = "\n\n"

        assert session["spaces"] == "   "
        assert session["tabs"] == "\t\t"

    def test_accepts_all_json_primitive_types(self, session):
        session["string"] = "text"
        session["number"] = 42
        session["float"] = 3.14
        session["bool_true"] = True
        session["bool_false"] = False
        session["null"] = None

        assert session["string"] == "text"
        assert session["number"] == 42
        assert session["float"] == 3.14
        assert session["bool_true"] is True
        assert session["bool_false"] is False
        assert session["null"] is None

    def test_accepts_empty_containers(self, session):
        session["empty_list"] = []
        session["empty_dict"] = {}

        assert session["empty_list"] == []
        assert session["empty_dict"] == {}

    def test_accepts_mixed_type_list(self, session):
        session["mixed"] = [1, "two", 3.0, True, None, {"key": "value"}]

        assert session["mixed"] == [1, "two", 3.0, True, None, {"key": "value"}]

    def test_accepts_very_long_strings(self, session):
        long_string = "x" * 10000

        session["long"] = long_string

        assert len(session["long"]) == 10000

    def test_accepts_large_numbers(self, session):
        session["large_int"] = 999999999999999
        session["large_float"] = 999999999999.999

        assert session["large_int"] == 999999999999999
        assert session["large_float"] == 999999999999.999

    def test_accepts_negative_numbers(self, session):
        session["neg_int"] = -42
        session["neg_float"] = -3.14

        assert session["neg_int"] == -42
        assert session["neg_float"] == -3.14

    def test_accepts_zero(self, session):
        session["zero_int"] = 0
        session["zero_float"] = 0.0

        assert session["zero_int"] == 0
        assert session["zero_float"] == 0.0


class TestSessionEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_session_initialization(self, session):
        """Test that new session starts empty"""
        assert len(session) == 0
        assert session.to_dict() == {}
        assert list(session) == []

    def test_session_with_only_none_values(self, session):
        session["key1"] = None
        session["key2"] = None
        session["key3"] = None

        assert len(session) == 3
        assert session["key1"] is None
        assert session["key2"] is None

    def test_session_with_mixed_none_and_values(self, session):
        session["user_id"] = "test"
        session["optional"] = None
        session["count"] = 0
        session["flag"] = False

        assert session["user_id"] == "test"
        assert session["optional"] is None
        assert session["count"] == 0
        assert session["flag"] is False

    def test_overwriting_existing_keys(self, session):
        session["key"] = "original"
        assert session["key"] == "original"

        session["key"] = "updated"
        assert session["key"] == "updated"

    def test_overwriting_with_different_types(self, session):
        session["key"] = "string"
        session["key"] = 42
        session["key"] = {"dict": "value"}
        session["key"] = ["list"]

        assert session["key"] == ["list"]

    def test_very_deeply_nested_structure(self, session):
        """Test with 10 levels of nesting"""
        deep = {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": {"l7": {"l8": {"l9": {"l10": "deep"}}}}}}}}}}

        session["deep"] = deep

        assert session["deep"]["l1"]["l2"]["l3"]["l4"]["l5"]["l6"]["l7"]["l8"]["l9"]["l10"] == "deep"

    def test_large_list(self, session):
        """Test with large list"""
        large_list = list(range(1000))

        session["large_list"] = large_list

        assert len(session["large_list"]) == 1000
        assert session["large_list"][500] == 500

    def test_large_dict(self, session):
        """Test with dictionary containing many keys"""
        large_dict = {f"key_{i}": f"value_{i}" for i in range(1000)}

        session["large_dict"] = large_dict

        assert len(session["large_dict"]) == 1000
        assert session["large_dict"]["key_500"] == "value_500"

    def test_special_key_names(self, session):
        """Test with various special characters in key names"""
        session["user-id"] = "dash"
        session["user_id"] = "underscore"
        session["user.id"] = "dot"
        session["user:id"] = "colon"
        session["user/id"] = "slash"

        assert session["user-id"] == "dash"
        assert session["user_id"] == "underscore"
        assert session["user.id"] == "dot"

    def test_numeric_string_keys(self, session):
        """Test with keys that look like numbers"""
        session["123"] = "numeric string key"
        session["0"] = "zero"

        assert session["123"] == "numeric string key"
        assert session["0"] == "zero"

    def test_boolean_false_vs_none(self, session):
        """Test distinction between False and None"""
        session["false"] = False
        session["none"] = None

        assert session["false"] is False
        assert session["none"] is None
        assert session["false"] != session["none"]

    def test_zero_vs_empty_string_vs_none(self, session):
        """Test distinction between falsy values"""
        session["zero"] = 0
        session["empty"] = ""
        session["none"] = None

        assert session["zero"] == 0
        assert session["empty"] == ""
        assert session["none"] is None
        assert session["zero"] != session["empty"]
        assert session["empty"] != session["none"]

    def test_session_with_all_json_types_mixed(self, session):
        """Test session containing every JSON type"""
        session["string"] = "text"
        session["number"] = 42
        session["float"] = 3.14
        session["bool"] = True
        session["null"] = None
        session["list"] = [1, 2, 3]
        session["dict"] = {"nested": "value"}

        assert len(session) == 7

    def test_replacing_simple_with_complex_type(self, session):
        """Test replacing simple value with complex structure"""
        session["data"] = "simple string"
        assert session["data"] == "simple string"

        session["data"] = {"complex": {"nested": ["structure"]}}
        assert session["data"]["complex"]["nested"] == ["structure"]

    def test_replacing_complex_with_simple_type(self, session):
        """Test replacing complex structure with simple value"""
        session["data"] = {"complex": {"nested": ["structure"]}}
        assert isinstance(session["data"], dict)

        session["data"] = "simple string"
        assert session["data"] == "simple string"

    def test_multiple_operations_sequence(self, session):
        """Test a sequence of various operations"""
        session["key1"] = "value1"
        session["key2"] = "value2"
        assert len(session) == 2

        del session["key1"]
        assert len(session) == 1

        session["key3"] = "value3"
        assert len(session) == 2

        session.clear()
        assert len(session) == 0

        session["new"] = "after clear"
        assert len(session) == 1

    def test_accessing_after_delete(self, session):
        """Test that accessing deleted key raises KeyError"""
        session["key"] = "value"
        del session["key"]

        with pytest.raises(KeyError):
            _ = session["key"]

        # But get() should return None
        assert session.get("key") is None

    def test_unicode_key_names(self, session):
        """Test with unicode characters in key names"""
        session["用户"] = "chinese key"
        session["émoji_🎉"] = "emoji in key"

        assert session["用户"] == "chinese key"
        assert session["émoji_🎉"] == "emoji in key"

    def test_whitespace_in_keys(self, session):
        """Test keys with whitespace"""
        session["key with spaces"] = "value"
        session[" leading"] = "value"
        session["trailing "] = "value"

        assert session["key with spaces"] == "value"
        assert session[" leading"] == "value"

    def test_empty_string_key(self, session):
        """Test with empty string as key"""
        session[""] = "empty key"

        assert session[""] == "empty key"
        assert "" in session

    def test_very_long_key_name(self, session):
        """Test with very long key name"""
        long_key = "k" * 1000

        session[long_key] = "value"

        assert session[long_key] == "value"
