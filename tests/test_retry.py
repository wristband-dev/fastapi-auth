import time
from unittest.mock import AsyncMock

import httpx
import pytest

from wristband.fastapi_auth.exceptions import WristbandError
from wristband.fastapi_auth.retry import (
    API_RETRY_DELAY_MULTIPLIER,
    API_RETRY_DELAY_SECONDS,
    MAX_API_RETRY_ATTEMPTS,
    with_retry,
)


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    response = httpx.Response(status_code, request=httpx.Request("GET", "https://example.com"))
    return httpx.HTTPStatusError(f"{status_code} error", request=response.request, response=response)


@pytest.mark.asyncio
async def test_resolves_on_first_attempt_without_retrying():
    fn = AsyncMock(return_value="result")

    result = await with_retry(fn)

    assert result == "result"
    assert fn.call_count == 1


@pytest.mark.asyncio
async def test_retries_on_a_5xx_http_status_error_and_eventually_succeeds():
    fn = AsyncMock(side_effect=[_http_status_error(500), _http_status_error(503), "result"])

    result = await with_retry(fn)

    assert result == "result"
    assert fn.call_count == 3


@pytest.mark.asyncio
async def test_retries_on_a_network_error_and_eventually_succeeds():
    fn = AsyncMock(side_effect=[httpx.ConnectError("Network failure"), "result"])

    result = await with_retry(fn)

    assert result == "result"
    assert fn.call_count == 2


@pytest.mark.asyncio
async def test_retries_on_a_wristband_error_with_a_5xx_status_code():
    fn = AsyncMock(side_effect=[WristbandError("unexpected_error", "boom", status_code=502), "result"])

    result = await with_retry(fn)

    assert result == "result"
    assert fn.call_count == 2


@pytest.mark.asyncio
async def test_does_not_retry_on_a_4xx_http_status_error():
    error = _http_status_error(400)
    fn = AsyncMock(side_effect=error)

    with pytest.raises(httpx.HTTPStatusError):
        await with_retry(fn)

    assert fn.call_count == 1


@pytest.mark.asyncio
async def test_does_not_retry_on_a_404_http_status_error():
    error = _http_status_error(404)
    fn = AsyncMock(side_effect=error)

    with pytest.raises(httpx.HTTPStatusError):
        await with_retry(fn)

    assert fn.call_count == 1


@pytest.mark.asyncio
async def test_does_not_retry_on_a_wristband_error_with_a_4xx_status_code():
    error = WristbandError("invalid_request", "bad request", status_code=400)
    fn = AsyncMock(side_effect=error)

    with pytest.raises(WristbandError):
        await with_retry(fn)

    assert fn.call_count == 1


@pytest.mark.asyncio
async def test_exhausts_retries_and_raises_the_last_error_on_persistent_5xx_failures():
    final_error = _http_status_error(500)
    fn = AsyncMock(side_effect=final_error)

    with pytest.raises(httpx.HTTPStatusError):
        await with_retry(fn)

    assert fn.call_count == MAX_API_RETRY_ATTEMPTS


@pytest.mark.asyncio
async def test_exhausts_retries_and_raises_the_last_error_on_persistent_network_failures():
    final_error = httpx.ConnectError("Persistent network failure")
    fn = AsyncMock(side_effect=final_error)

    with pytest.raises(httpx.ConnectError):
        await with_retry(fn)

    assert fn.call_count == MAX_API_RETRY_ATTEMPTS


@pytest.mark.asyncio
async def test_waits_between_retry_attempts():
    fn = AsyncMock(side_effect=[_http_status_error(500), "result"])

    start_time = time.monotonic()
    await with_retry(fn)
    elapsed = time.monotonic() - start_time

    assert elapsed >= API_RETRY_DELAY_SECONDS - 0.01


@pytest.mark.asyncio
async def test_does_not_wait_after_a_non_retryable_error():
    fn = AsyncMock(side_effect=_http_status_error(400))

    start_time = time.monotonic()
    with pytest.raises(httpx.HTTPStatusError):
        await with_retry(fn)
    elapsed = time.monotonic() - start_time

    assert elapsed < API_RETRY_DELAY_SECONDS


@pytest.mark.asyncio
async def test_applies_exponential_backoff_multiplying_the_delay_after_each_retry():
    fn = AsyncMock(side_effect=[_http_status_error(500), _http_status_error(500), "result"])

    expected_min_elapsed = API_RETRY_DELAY_SECONDS + API_RETRY_DELAY_SECONDS * API_RETRY_DELAY_MULTIPLIER

    start_time = time.monotonic()
    await with_retry(fn)
    elapsed = time.monotonic() - start_time

    assert elapsed >= expected_min_elapsed - 0.01
