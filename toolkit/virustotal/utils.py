"""Module defining some helper functions used across the project."""

import asyncio
import typing


def make_sync(future: typing.Coroutine):
    """Utility function that waits for an async call, making it sync."""
    try:
        event_loop = asyncio.get_event_loop()
    except RuntimeError:
        # Generate an event loop if there isn't any.
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
    return event_loop.run_until_complete(future)
