import logging
from contextlib import suppress
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from decima import CustomLogger

from praetor.connection.socket_manager import SocketManager
from praetor.protocol_info import ProtocolInfo, ResponseValidators, normalize_protocol_infos, resolve_response_validator


class _DeviceValidator:
    """Validator class for validating protocol packets against a live device using Wireshark parsing."""

    def __init__(self, protocols: list[ProtocolInfo], is_valid_response: ResponseValidators) -> None:
        """Initialize the DeviceValidator with the specified protocols.

        Args:
            protocols: Protocol names to validate against.
            is_valid_response: A response validator callable shared by all protocols, or a mapping of protocol names to protocol-specific validators.
        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._protocol_infos: tuple[ProtocolInfo, ...] = normalize_protocol_infos(protocols)
        self._response_validators = {protocol_info: resolve_response_validator(is_valid_response, protocol_info) for protocol_info in self._protocol_infos}
        self._socket_managers: dict[ProtocolInfo, SocketManager] = {}

        try:
            for protocol_info in self._protocol_infos:
                socket_manager = SocketManager("localhost", protocol_info.custom_port, protocol_info.protocol_name, timeout=0.05)
                socket_manager.connect()
                self._socket_managers[protocol_info] = socket_manager
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Release the managed socket and stop the local cursus server."""
        for socket_manager in self._socket_managers.values():
            socket_manager.shutdown()
        self._socket_managers.clear()

    def __del__(self) -> None:
        """Best-effort cleanup for cached validators."""
        with suppress(Exception):
            self.close()

    def _selected_protocol_info(self, protocol: str) -> ProtocolInfo:
        """Return the protocol metadata selected for validation."""
        requested_protocol = ProtocolInfo.from_name(protocol)
        if requested_protocol not in self._protocol_infos:
            raise ValueError(f"Protocol is not configured for this validator: {protocol}")
        return requested_protocol

    def validate(self, packet: str, *, protocol: str) -> bytes:
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
        protocol_info = self._selected_protocol_info(protocol)
        return self._validate_protocol(packet, protocol_info)

    def _validate_protocol(self, packet: str, protocol_info: ProtocolInfo) -> bytes:
        """Validate the packet against one configured protocol."""
        response: bytes = b""
        socket_manager = self._socket_managers[protocol_info]
        try:
            socket_manager.send(bytes.fromhex(packet))
            response: bytes = socket_manager.receive(1024)
            if len(response) == 0:
                raise ValueError(f"No response received for packet: {packet}")
        except OSError:
            self.logger.debug("Socket error detected, reconnecting...")
            socket_manager.reconnect()
            raise

        is_valid_response = self._response_validators[protocol_info]
        if not is_valid_response(response.hex()):
            raise ValueError(f"No response or unexpected response for packet: {packet}, cannot dissect.")

        self.logger.debug(f"[+] Dissecting packet: {packet} : {response.hex()} for protocol layers: {protocol_info.scapy_names}")
        return response
