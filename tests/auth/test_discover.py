from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from wristband.fastapi_auth.auth import WristbandAuth
from wristband.fastapi_auth.exceptions import WristbandError
from wristband.fastapi_auth.models import AuthConfig


@pytest_asyncio.fixture
async def mock_auth_config():
    return AuthConfig(
        client_id="test-client",
        client_secret="test-secret",
        login_state_secret="a" * 32,
        login_url="https://example.com/login",
        redirect_uri="https://example.com/callback",
        wristband_application_vanity_domain="example.wristband.dev",
        auto_configure_enabled=True,
    )


@pytest.mark.asyncio
async def test_discover_raises_if_auto_configure_disabled(mock_auth_config):
    mock_auth_config.auto_configure_enabled = False
    auth = WristbandAuth(mock_auth_config)

    with pytest.raises(WristbandError) as exc:
        await auth.discover()

    assert "auto_configure_enabled is false" in str(exc.value)


@pytest.mark.asyncio
async def test_discover_calls_preload_sdk_config(mock_auth_config):
    auth = WristbandAuth(mock_auth_config)

    # Patch resolver to spy on preload_sdk_config
    mock_preload = AsyncMock()
    auth._config_resolver.preload_sdk_config = mock_preload

    await auth.discover()

    mock_preload.assert_awaited_once()
