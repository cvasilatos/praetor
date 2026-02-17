import logging
import random
from typing import TYPE_CHECKING, cast

from pyshark.packet.packet import Packet

if TYPE_CHECKING:
    from logger_captain.logger import CustomLogger
    from pyshark.packet.layers.base import BaseLayer
    from pyshark.packet.layers.json_layer import JsonLayer
    from scapy.packet import Packet as ScapyPacket

from concurrent.futures import ThreadPoolExecutor

from pyshark.capture.inmem_capture import InMemCapture
from scapy.all import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from protocol_validator.protocol_info import ProtocolInfo
from protocol_validator.validator_error import ValidatorError
from protocol_validator.validator_wireshark_error import ValidatorWiresharkError


class AsyncPacketValidator:
    def __init__(self, protocol: str) -> None:
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self._protocol: str = protocol
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)

        self._override_prefs: dict[str, str] = {}
        if self._protocol == "mbtcp":
            self._override_prefs["mbtcp.tcp.port"] = str(self._protocol_info.port)

        self._tcp_seq: int = 0
        self._tcp_ack: int = 0

        self._next_tcp_seq: int = 1
        self._next_tcp_ack: int = 1

        self._executor = ThreadPoolExecutor(max_workers=1)

    def validate(self, packet: str, *, is_request: bool) -> Packet:
        future = self._executor.submit(self.validate_thread, packet, is_request=is_request)
        return future.result()

    def validate_thread(self, packet: str, *, is_request: bool) -> Packet:
        payload_bytes = bytes.fromhex(packet)
        payload_len = len(payload_bytes)

        seq = self._tcp_seq
        ack = self._tcp_ack

        step = max(1, payload_len)
        next_seq = (seq + step) % (2**32)
        next_ack = (ack + step) % (2**32)

        self._next_tcp_seq = next_seq
        self._next_tcp_ack = next_ack

        tcp_layer: ScapyPacket
        if is_request:
            if self._protocol == "bacnet":
                tcp_layer = UDP(sport=47808, dport=self._protocol_info.port)
            else:
                tcp_layer = TCP(
                    sport=random.randint(1024, 65535),
                    dport=self._protocol_info.port,
                    flags="PA",
                    seq=seq,
                    ack=ack,
                )
        else:
            tcp_layer = TCP(
                sport=self._protocol_info.port,
                dport=random.randint(1024, 65535),
                flags="PA",
                seq=seq,
                ack=ack,
            )

        full_packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.10", dst="192.168.1.20") / tcp_layer / Raw(load=payload_bytes)

        cap = InMemCapture(override_prefs=self._override_prefs)
        parsed_packet: Packet = cap.parse_packet(bytes(full_packet))
        cap.clear()

        self._tcp_seq = next_seq
        self._tcp_ack = next_ack

        self.logger.debug(f"Validating packet (is_request={is_request}): {bytes(full_packet).hex()}")
        layer: JsonLayer
        for layer in parsed_packet.layers:
            if layer.layer_name not in {"tcp", "eth", "ip"}:
                self.logger.trace(f"Validate protocol related layer (is_request={is_request}): {layer}")

        temp_layer: JsonLayer
        for temp_layer in parsed_packet.layers:
            if temp_layer.get_field("_ws_expert"):
                error_msg: str = temp_layer.get_field("_ws_expert_message")
                error_group: str = temp_layer.get_field("_ws_group")
                error_severity: str = temp_layer.get_field("_ws_severity")
                raise ValidatorWiresharkError(f"Validation failed, Error: {error_msg} (Group: {error_group}, Severity: {error_severity})", parsed_packet, is_request=is_request)

        layer_names: list[BaseLayer] = [layer.layer_name for layer in cast("list[BaseLayer]", parsed_packet.layers)]
        is_contained: bool = set(self._protocol_info.scapy_names).issubset(set(layer_names))
        if not is_contained:
            raise ValidatorError(f"Validation failed, no layer '{self._protocol_info.scapy_names}'", parsed_packet, is_request=is_request)

        self.logger.trace(f"Validation successful for packet {is_request}: {parsed_packet}")

        return parsed_packet
