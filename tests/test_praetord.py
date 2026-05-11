"""Tests for Praetor lifecycle behavior."""

from unittest.mock import MagicMock, patch

from praetor.praetord import Praetor
from praetor.protocol_info import ProtocolInfo


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


def test_init_accepts_multiple_protocols() -> None:
    """Praetor should expose canonical names for multi-protocol validators."""
    device_validator = MagicMock()
    device_validator.protocol_names = ("mbtcp", "s7comm")
    pyshark_validator = MagicMock()

    with (
        patch("praetor.praetord._DeviceValidator", return_value=device_validator),
        patch("praetor.praetord._PysharkValidator", return_value=pyshark_validator),
        patch(
            "praetor.praetord.CombinedValidator.from_validators",
            return_value=MagicMock(),
        ),
    ):
        validator = Praetor(
            [ProtocolInfo.MBTCP, ProtocolInfo.S7COMM],
            lambda response_hex: bool(response_hex),
        )

    assert validator.protocols == ("mbtcp", "s7comm")
