"""Tests for Praetor lifecycle behavior."""

from unittest.mock import MagicMock

from praetor.praetord import Praetor


def test_del_ignores_missing_validators() -> None:
    """Partially initialized instances should not raise during destruction."""
    validator = Praetor.__new__(Praetor)

    validator.__del__()


def test_del_attempts_both_validator_cleanups() -> None:
    """Cleanup should continue even if one validator close fails."""
    validator = Praetor.__new__(Praetor)
    validator._device_validator = MagicMock()
    validator._pyshark_validator = MagicMock()
    validator._device_validator.close.side_effect = RuntimeError("close failed")

    validator.__del__()

    validator._device_validator.close.assert_called_once()
    validator._pyshark_validator.close.assert_called_once()
