"""Module for the base class of protocol validation using Cursusd and Wireshark."""

import logging
import secrets
from typing import TYPE_CHECKING, cast

import pyshark
from pyshark.packet.layers.base import BaseLayer

if TYPE_CHECKING:
    from decima.logger import CustomLogger
    from pyshark.packet.packet import Packet


from scapy.all import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from praetor.exceptions.validator_error import ValidatorError
from praetor.exceptions.validator_wireshark_error import ValidatorWiresharkError
from praetor.protocol_info import ProtocolInfo


class _PysharkValidator:
    """Base class for protocol validation using Cursusd and Wireshark."""

    def __init__(self, protocol: str) -> None:
        """Initialize the ValidatorBase with the specified protocol."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.protocol: str = protocol
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self.scapy_names: list[str] = self._protocol_info.scapy_names

        override_prefs: dict[str, str] = {}
        if self.protocol == "mbtcp":
            override_prefs["mbtcp.tcp.port"] = str(self._protocol_info.port)

        self._cap = pyshark.InMemCapture(override_prefs=override_prefs, custom_parameters={"-o": "tcp.analyze_sequence_numbers:FALSE"})

        self._tcp_seq: int = 0
        self._tcp_ack: int = 0

        self._next_tcp_seq: int = 1
        self._next_tcp_ack: int = 1

    def __del__(self) -> None:
        """Clean up resources when the ValidatorBase instance is destroyed."""
        if self._cap:
            self._cap.close()

    def validate(self, packet: str, *, is_request: bool) -> BaseLayer:
        """Validate the given packet bytes (in hex) as either a request or response.

        Args:
            packet: str - The packet bytes in hexadecimal string format.
            is_request: bool - Whether to treat the packet as a request (True) or response (False).

        Returns:
            BaseLayer - The protocol-specific layer if validation is successful.

        Raises:
            ValidatorWiresharkError: If Wireshark parsing detects an error in the packet.
            ValidatorError: If the expected protocol layer is not found in the parsed packet.

        Description:
            This method constructs a full Ethernet/IP/TCP or Ethernet/IP/UDP packet with the given payload, parses it using pyshark, and checks for protocol-specific
            layers and Wireshark expert info.

        """
        payload_bytes: bytes = bytes.fromhex(packet)
        payload_len: int = len(payload_bytes)

        seq: int = self._tcp_seq
        ack: int = self._tcp_ack

        step: int = max(1, payload_len)
        next_seq: int = (seq + step) % (2**32)
        next_ack: int = (ack + step) % (2**32)

        self._next_tcp_seq = next_seq
        self._next_tcp_ack = next_ack

        tcp_layer: TCP | UDP | None = None
        if is_request:
            if self.protocol == "bacnet":
                tcp_layer = UDP(sport=47808, dport=self._protocol_info.port)
            else:
                tcp_layer = TCP(
                    sport=secrets.randbelow(65535 - 1024 + 1) + 1024,
                    dport=self._protocol_info.port,
                    flags="PA",
                    seq=seq,
                    ack=ack,
                )
        else:
            tcp_layer = TCP(
                sport=self._protocol_info.port,
                dport=secrets.randbelow(65535 - 1024 + 1) + 1024,
                flags="PA",
                seq=seq,
                ack=ack,
            )

        full_packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.10", dst="192.168.1.20") / tcp_layer / Raw(load=payload_bytes)

        parsed_packet: Packet = self._cap.parse_packet(bytes(full_packet))
        self._cap.clear()

        self._tcp_seq = next_seq
        self._tcp_ack = next_ack

        self.logger.debug(f"Validating packet (is_request={is_request}): {bytes(full_packet).hex()}")
        layer: BaseLayer
        for layer in parsed_packet.layers:
            if layer.layer_name not in {"tcp", "eth", "ip"}:
                self.logger.debug(f"Validate protocol related layer (is_request={is_request}): {layer}")

        temp_layer: BaseLayer
        for temp_layer in parsed_packet.layers:
            if temp_layer.get_field("_ws_expert"):
                error_msg: str = temp_layer.get_field("_ws_expert_message")
                error_group: str = temp_layer.get_field("_ws_group")
                error_severity: str = temp_layer.get_field("_ws_severity")
                raise ValidatorWiresharkError(f"Validation failed, Error: {error_msg} (Group: {error_group}, Severity: {error_severity})", parsed_packet, is_request=is_request)

        layer_names: list[str] = [layer.layer_name for layer in cast("list[BaseLayer]", parsed_packet.layers)]
        is_contained: bool = set(self.scapy_names).issubset(set(layer_names))
        if not is_contained:
            raise ValidatorError(f"Validation failed, no layer '{self.scapy_names}'", parsed_packet, is_request=is_request)

        self.logger.trace(f"Validation successful for packet {is_request}: {parsed_packet}")

        return parsed_packet
