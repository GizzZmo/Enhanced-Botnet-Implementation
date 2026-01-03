import asyncio
import warnings

import pytest


@pytest.fixture(autouse=True, scope="session")
def ensure_event_loop():
    """Ensure an event loop is available for the test session."""
    with warnings.catch_warnings():
        # Suppress only the deprecation warning triggered when no loop is set.
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message="There is no current event loop",
        )
        try:
            original_loop = asyncio.get_event_loop()
        except RuntimeError:
            original_loop = None

    loop = original_loop
    created_new = False
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        created_new = True

    yield

    if created_new:
        loop.close()
        restore_loop = (
            original_loop
            if original_loop is not None and not original_loop.is_closed()
            else None
        )
        asyncio.set_event_loop(restore_loop)
