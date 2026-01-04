import asyncio
import threading
import warnings

import pytest


def ensure_loop():
    """
    Ensure an event loop exists for the current thread.

    This helper is intended for synchronous tests that instantiate asyncio
    primitives outside of an async context.

    Note: Only the main thread is managed here; worker threads are expected
    to create and manage their own event loops if needed.
    """
    if threading.current_thread() is not threading.main_thread():
        return
    policy = asyncio.get_event_loop_policy()
    try:
        policy.get_event_loop()
    except RuntimeError:
        policy.set_event_loop(policy.new_event_loop())


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

    ensure_loop()
    loop = asyncio.get_event_loop()
    created_new = original_loop is None or original_loop.is_closed()

    yield

    if created_new and loop is not None and not loop.is_closed():
        loop.close()
        restore_loop = (
            original_loop
            if original_loop is not None and not original_loop.is_closed()
            else None
        )
        asyncio.set_event_loop(restore_loop)
