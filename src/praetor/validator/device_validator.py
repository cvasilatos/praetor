import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from decima import CustomLogger

from praetor.connection.socket_manager import SocketManager
from praetor.protocol_info import ProtocolInfo


class _DeviceValidator:
    """Validator class for validating protocol packets against a live device using Wireshark parsing."""

    def __init__(self, protocol: str, is_valid_response: Callable) -> None:
        """Initialize the DeviceValidator with the specified protocol.

        Args:
            protocol (str): The name of the protocol to validate against (e.g., "mbtcp", "s7comm", etc.).
            is_valid_response (Callable): A callable that takes a bytes object (the response from the device) and returns a boolean indicating
            whether the response is valid for the given protocol.
        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._socket_manager = SocketManager("localhost", self._protocol_info.custom_port, protocol, timeout=0.05)
        self._socket_manager.connect()
        self._is_valid_response = is_valid_response

    def validate(self, packet: str) -> bytes:
        """Validate the seed packet by sending it to the target server and analyzing the response.

        Returns:
            bytes: The response from the server if it is valid according to the provided is_valid function.

        Raises:
            OSError: If the socket crashes during send or receive, after closing and reconnecting.
            ValueError: If no response or an unexpected response is received for the seed packet, indicating that it cannot be dissected.

        Description:
            The method sends the seed packet to the server and waits for a response. If a valid response is received,
            it uses PyShark to dissect the packet and extract protocol layers. If no response or an unexpected response is received, it raises a ValueError indicating
            that the seed cannot be dissected. If the socket crashes, all socket resources are closed and the connection is re-established before re-raising.

        """
        response: bytes = b""
        try:
            self._socket_manager.send(bytes.fromhex(packet))
            response: bytes = self._socket_manager.receive(1024)
        except OSError:
            self.logger.debug("Socket error detected, reconnecting...")
            self._socket_manager.reconnect()
            raise

        if not self._is_valid_response(response.hex()):
            raise ValueError(f"No response or unexpected response for packet: {packet}, cannot dissect.")

        self.logger.debug(f"[+] Dissecting packet: {packet} : {response.hex()} for protocol layers: {self._protocol_info.scapy_names}")
        return response
