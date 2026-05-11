"""Tests for CombinedValidator orchestration."""

from unittest.mock import MagicMock, patch

from praetor.validator.combined_validator import CombinedValidator


def test_validate_checks_pyshark_and_device_validators() -> None:
    """Combined validation should pass only when both validators accept the packet."""
    device_validator = MagicMock()
    pyshark_validator = MagicMock()

    with (
        patch(
            "praetor.validator.combined_validator._DeviceValidator",
            return_value=device_validator,
        ),
        patch(
            "praetor.validator.combined_validator._PysharkValidator",
            return_value=pyshark_validator,
        ),
    ):
        validator = CombinedValidator("mbtcp", lambda response_hex: bool(response_hex))

    assert validator.validate("deadbeef") is True
    pyshark_validator.validate.assert_called_once_with("deadbeef", is_request=False)
    device_validator.validate.assert_called_once_with("deadbeef")


def test_validate_returns_false_for_validation_error() -> None:
    """Validation failures should become a False packet-validity result."""
    device_validator = MagicMock()
    pyshark_validator = MagicMock()
    pyshark_validator.validate.side_effect = ValueError("invalid packet")

    with (
        patch(
            "praetor.validator.combined_validator._DeviceValidator",
            return_value=device_validator,
        ),
        patch(
            "praetor.validator.combined_validator._PysharkValidator",
            return_value=pyshark_validator,
        ),
    ):
        validator = CombinedValidator("mbtcp", lambda response_hex: bool(response_hex))

    assert validator.validate("deadbeef") is False
    device_validator.validate.assert_not_called()
