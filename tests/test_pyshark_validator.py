"""Tests for _PysharkValidator event loop handling."""

import asyncio
from collections.abc import Generator
from contextlib import suppress
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from praetor.protocol_info import ProtocolInfo
from praetor.validator.pyshark_validator import _PysharkValidator


@pytest.fixture
def _restore_event_loop() -> Generator[None, None, None]:
    """Restore the caller's current event loop after each test."""
    previous_event_loop = None
    with suppress(RuntimeError):
        previous_event_loop = asyncio.get_event_loop()

    try:
        yield
    finally:
        if previous_event_loop is not None and not previous_event_loop.is_closed():
            asyncio.set_event_loop(previous_event_loop)
        else:
            asyncio.set_event_loop(None)


def test_init_creates_private_event_loop_when_no_current_loop(
    _restore_event_loop: None,
) -> None:
    """Synchronous callers should get a private loop on Python 3.14+."""
    asyncio.set_event_loop(None)

    capture: SimpleNamespace | None = None

    def fake_inmem_capture(**kwargs: object) -> SimpleNamespace:
        nonlocal capture
        capture = SimpleNamespace(eventloop=kwargs["eventloop"])
        return capture

    with (
        patch(
            "praetor.validator.pyshark_validator.pyshark.InMemCapture",
            side_effect=fake_inmem_capture,
        ),
    ):
        validator = _PysharkValidator([ProtocolInfo.MBTCP])

    assert capture is not None
    assert validator._owns_event_loop is True
    assert isinstance(capture.eventloop, asyncio.AbstractEventLoop)
    assert asyncio.get_event_loop() is capture.eventloop

    validator.close()

    assert capture.eventloop.is_closed()
    with pytest.raises(RuntimeError, match="There is no current event loop"):
        asyncio.get_event_loop()


def test_init_uses_supplied_event_loop_without_owning_it(
    _restore_event_loop: None,
) -> None:
    """Callers can supply an event loop that remains under their control."""
    event_loop = asyncio.new_event_loop()
    capture: SimpleNamespace | None = None

    def fake_inmem_capture(**kwargs: object) -> SimpleNamespace:
        nonlocal capture
        capture = SimpleNamespace(eventloop=kwargs["eventloop"])
        return capture

    with (
        patch(
            "praetor.validator.pyshark_validator.pyshark.InMemCapture",
            side_effect=fake_inmem_capture,
        ),
    ):
        validator = _PysharkValidator([ProtocolInfo.MBTCP], event_loop=event_loop)

    assert capture is not None
    assert validator._owns_event_loop is False
    assert capture.eventloop is event_loop

    validator.close()

    assert event_loop.is_closed() is False
    event_loop.close()
