import asyncio
import pytest


@pytest.fixture(autouse=True, scope="session")
def ensure_event_loop():
    """Ensure an event loop is available for tests running in the main thread."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield
