"""Module for the base class of protocol validation using Cursusd and Wireshark."""

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from pyshark.packet.layers.base import BaseLayer

from praetor.validator.device_validator import DeviceValidator
from praetor.validator.pyshark_validator import PysharkValidator

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class Praetor:
    """Base class for protocol validation using Cursusd and Wireshark."""

    def __init__(self, protocol: str, is_valid_response: Callable) -> None:
        """Initialize the ValidatorBase with the specified protocol."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.protocol: str = protocol

        self._device_validator = DeviceValidator(protocol, is_valid_response)
        self._pyshark_validator = PysharkValidator(protocol)

    def validate(self, packet: str, *, is_request: bool, run_on_device: bool) -> tuple[bytes | None, BaseLayer]:
        """Validate the given packet bytes (in hex) as either a request or response.

        Args:
            packet: str - The packet bytes in hexadecimal string format.
            is_request: bool - Whether to treat the packet as a request (True) or response (False).
            run_on_device: bool - Whether to run the validation against a live device (True) or just use PyShark (False).

        Description:
            The method first validates the seed packet by sending it to the target server and analyzing the response.
            If a valid response is received, it uses PyShark to dissect the packet and extract protocol
        """
        if run_on_device:
            response: bytes = self._device_validator.validate_seed(packet)
        else:
            response = None

        base_layer: BaseLayer = self._pyshark_validator.validate(packet, is_request=is_request)

        return response, base_layer

    @property
    def device_validator(self) -> DeviceValidator:
        """Return the DeviceValidator instance."""
        return self._device_validator

    @property
    def pyshark_validator(self) -> PysharkValidator:
        """Return the PySharkValidator instance."""
        return self._pyshark_validator
