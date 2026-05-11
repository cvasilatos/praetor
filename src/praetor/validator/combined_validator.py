"""Combined protocol validation using device and PyShark validators."""

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Self, cast

from praetor.exceptions.validator_error import ValidatorError
from praetor.exceptions.validator_wireshark_error import ValidatorWiresharkError
from praetor.validator.device_validator import _DeviceValidator
from praetor.validator.pyshark_validator import _PysharkValidator

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class CombinedValidator:
    """Run device and PyShark validation through a single validator."""

    def __init__(self, protocol: str, is_valid_response: Callable[[str], bool], *, event_loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Initialize a combined validator that owns its validator resources."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._device_validator: _DeviceValidator = _DeviceValidator(protocol, is_valid_response)
        self._pyshark_validator: _PysharkValidator = _PysharkValidator(protocol, event_loop=event_loop)

    @classmethod
    def from_validators(cls, device_validator: _DeviceValidator, pyshark_validator: _PysharkValidator) -> Self:
        """Create a combined validator that shares the provided validator resources."""
        instance = cls.__new__(cls)
        instance.logger = cast("CustomLogger", logging.getLogger(f"{cls.__module__}.{cls.__name__}"))
        instance.set_device_validator(device_validator)
        instance.set_pyshark_validator(pyshark_validator)
        return instance

    def set_device_validator(self, device_validator: _DeviceValidator) -> None:
        """Set the DeviceValidator instance."""
        self._device_validator = device_validator

    def set_pyshark_validator(self, pyshark_validator: _PysharkValidator) -> None:
        """Set the PySharkValidator instance."""
        self._pyshark_validator = pyshark_validator

    def validate(self, packet: str) -> bool:
        """Validate a request packet with both validators and return the device response.

        The request payload is parsed with PyShark, sent to the device validator, and
        the returned response is parsed with PyShark as a response payload.
        """
        try:
            self._pyshark_validator.validate(packet, is_request=False)
            self._device_validator.validate(packet)

            self.logger.debug(f"Combined validation successful for packet: {packet}")
        except (ValueError, OSError, ValidatorError, ValidatorWiresharkError) as e:
            self.logger.debug(f"Combined validation failed for packet: {packet}: {e}")
            return False
        return True
