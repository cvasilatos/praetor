"""Combined protocol validation using device and PyShark validators."""

import asyncio
import logging
from typing import TYPE_CHECKING, Self, cast

from praetor.exceptions.validator_error import ValidatorError
from praetor.exceptions.validator_wireshark_error import ValidatorWiresharkError
from praetor.protocol_info import ProtocolInfo, ResponseValidators, normalize_protocol_infos, protocol_names
from praetor.validator.device_validator import _DeviceValidator
from praetor.validator.pyshark_validator import _PysharkValidator

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class CombinedValidator:
    """Run device and PyShark validation through a single validator."""

    def __init__(self, protocols: list[ProtocolInfo], is_valid_response: ResponseValidators, *, event_loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Initialize a combined validator that owns its validator resources."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._protocol_names: tuple[str, ...] = protocol_names(normalize_protocol_infos(protocols))
        self._device_validator: _DeviceValidator = _DeviceValidator(protocols, is_valid_response)
        self._pyshark_validator: _PysharkValidator = _PysharkValidator(protocols, event_loop=event_loop)

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

    def _selected_protocol_name(self, protocol: str) -> str:
        """Return the canonical protocol selected for this validation call."""
        protocol_name = ProtocolInfo.from_name(protocol).protocol_name
        if protocol_name not in self._protocol_names:
            raise ValueError(f"Protocol is not configured for this validator: {protocol}")
        return protocol_name

    def validate(self, packet: str, *, protocol: str) -> bool:
        """Validate a request packet with both validators and return the device response.

        The request payload is parsed with PyShark, sent to the device validator, and
        the returned response is parsed with PyShark as a response payload.
        """
        protocol_name = self._selected_protocol_name(protocol)

        try:
            self._pyshark_validator.validate(packet, is_request=False, protocol=protocol_name)
            self._device_validator.validate(packet, protocol=protocol_name)
        except (ValueError, OSError, ValidatorError, ValidatorWiresharkError) as e:
            self.logger.debug(f"Combined validation failed for packet: {packet}, protocol={protocol_name}: {e}")
            return False

        self.logger.debug(f"Combined validation successful for packet: {packet}, protocol={protocol_name}")
        return True
