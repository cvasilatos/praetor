"""Module for base error class for protocol validation errors."""

from scapy.packet import Packet


class BaseError(ValueError):
    """Base error class for protocol validation errors."""

    def __init__(self, message: str, pdu: Packet, *, is_request: bool) -> None:
        """Initialize the BaseError with a message, the PDU that caused the error, and whether it was a request or response."""
        super().__init__(message)
        self._pdu: Packet = pdu
        self._is_request: bool = is_request

    @property
    def pdu(self) -> Packet:
        """Return the PDU that caused the error."""
        return self._pdu

    @property
    def is_request(self) -> bool:
        """Return whether the PDU was a request."""
        return self._is_request
