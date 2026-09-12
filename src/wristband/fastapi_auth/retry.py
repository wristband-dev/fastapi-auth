import asyncio
from typing import Awaitable, Callable, TypeVar

import httpx

from .exceptions import WristbandError

T = TypeVar("T")

MAX_API_RETRY_ATTEMPTS = 3
API_RETRY_DELAY_SECONDS = 0.1  # 100 milliseconds
API_RETRY_DELAY_MULTIPLIER = 2


def _is_retryable_error(error: Exception) -> bool:
    """
    Determines whether a failed API call should be retried.

    Only transient failures are retried: 5xx responses and network-level errors
    (connection issues, timeouts, etc). 4xx responses indicate a client-side
    problem that a retry cannot fix, so they are never retried.
    """
    if isinstance(error, httpx.HTTPStatusError):
        return error.response.status_code >= 500
    if isinstance(error, WristbandError) and error.status_code is not None:
        return error.status_code >= 500
    return True


async def with_retry(fn: Callable[[], Awaitable[T]]) -> T:
    """
    Invokes the given async callable, retrying on transient failures with
    exponential backoff.

    Retries up to MAX_API_RETRY_ATTEMPTS times, waiting API_RETRY_DELAY_SECONDS
    after the first failure and multiplying the delay by API_RETRY_DELAY_MULTIPLIER
    after each subsequent failure. Only retries errors classified as transient by
    _is_retryable_error(); all other errors are raised immediately.

    Args:
        fn: A zero-argument async callable to invoke (and retry, if needed).

    Returns:
        The result of `fn()` once it succeeds.

    Raises:
        The last exception raised by `fn()` if all attempts are exhausted, or
        immediately if the error is not retryable.
    """
    delay_seconds = API_RETRY_DELAY_SECONDS
    last_error: Exception = RuntimeError("with_retry: no attempts were made")

    for attempt in range(1, MAX_API_RETRY_ATTEMPTS + 1):
        try:
            return await fn()
        except Exception as error:
            last_error = error
            if attempt == MAX_API_RETRY_ATTEMPTS or not _is_retryable_error(error):
                raise
            await asyncio.sleep(delay_seconds)
            delay_seconds *= API_RETRY_DELAY_MULTIPLIER

    raise last_error
