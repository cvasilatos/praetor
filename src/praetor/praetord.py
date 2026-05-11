"""Module for the base class of protocol validation using Cursusd and Wireshark."""

import logging
from collections.abc import Callable
from contextlib import suppress
from typing import TYPE_CHECKING, cast

from praetor.validator.combined_validator import CombinedValidator
from praetor.validator.device_validator import _DeviceValidator
from praetor.validator.pyshark_validator import _PysharkValidator

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class Praetor:
    """Base class for protocol validation using Cursusd and Wireshark."""

    def __init__(self, protocol: str, is_valid_response: Callable) -> None:
        """Initialize the ValidatorBase with the specified protocol."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.protocol: str = protocol

        self._device_validator = _DeviceValidator(protocol, is_valid_response)
        self._pyshark_validator = _PysharkValidator(protocol)
        self._combined_validator = CombinedValidator.from_validators(self._device_validator, self._pyshark_validator)

    @property
    def device_validator(self) -> _DeviceValidator:
        """Return the DeviceValidator instance."""
        return self._device_validator

    @property
    def pyshark_validator(self) -> _PysharkValidator:
        """Return the PySharkValidator instance."""
        return self._pyshark_validator

    @property
    def combined_validator(self) -> CombinedValidator:
        """Return the CombinedValidator instance."""
        return self._combined_validator

    def __del__(self) -> None:
        """Clean up resources when the Praetor instance is deleted."""
        with suppress(Exception):
            self._device_validator.close()
        with suppress(Exception):
            self._pyshark_validator.close()
