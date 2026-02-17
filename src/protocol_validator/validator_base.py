import logging
import random
from typing import TYPE_CHECKING, cast

import pyshark

if TYPE_CHECKING:
    from cfg.log_configuration import CustomLogger
    from pyshark.packet.layers.base import BaseLayer
    from pyshark.packet.packet import Packet


import argparse
import sys

from scapy.all import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from protocol_validator.protocol_info import ProtocolInfo
from protocol_validator.validator_error import ValidatorError
from protocol_validator.validator_wireshark_error import ValidatorWiresharkError


class ValidatorBase:
    def __init__(self, protocol: str) -> None:
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.protocol = protocol
        self._protocol_info = ProtocolInfo.from_name(protocol)
        self.scapy_names = self._protocol_info.scapy_names

        override_prefs = {}
        if self.protocol == "mbtcp":
            override_prefs["mbtcp.tcp.port"] = str(self._protocol_info.port)

        self._cap = pyshark.InMemCapture(override_prefs=override_prefs, custom_parameters={"-o": "tcp.analyze_sequence_numbers:FALSE"})

        self._tcp_seq = 0
        self._tcp_ack = 0

        self._next_tcp_seq = 1
        self._next_tcp_ack = 1

    def __del__(self) -> None:
        if self._cap:
            self._cap.close()

    def validate(self, packet: str, *, is_request: bool) -> BaseLayer:
        payload_bytes = bytes.fromhex(packet)
        payload_len = len(payload_bytes)

        seq = self._tcp_seq
        ack = self._tcp_ack

        step = max(1, payload_len)
        next_seq = (seq + step) % (2**32)
        next_ack = (ack + step) % (2**32)

        self._next_tcp_seq = next_seq
        self._next_tcp_ack = next_ack

        tcp_layer: TCP | UDP | None = None
        if is_request:
            if self.protocol == "bacnet":
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

        layer_names = [layer.layer_name for layer in cast("list[BaseLayer]", parsed_packet.layers)]
        is_contained = set(self.scapy_names).issubset(set(layer_names))
        if not is_contained:
            raise ValidatorError(f"Validation failed, no layer '{self.scapy_names}'", parsed_packet, is_request=is_request)

        self.logger.trace(f"Validation successful for packet {is_request}: {parsed_packet}")

        return parsed_packet


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate protocol packet")
    parser.add_argument("packet", nargs="?", default="000100000006010300000002", help="Packet bytes in hex")
    parser.add_argument("-p", "--protocol", default="mbtcp", help="Protocol name (mbtcp, s7comm, iec104, dnp3)")
    group: argparse._MutuallyExclusiveGroup = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--request", action="store_true", help="Treat packet as request (default)")
    group.add_argument("-s", "--response", action="store_true", help="Treat packet as response")
    args = parser.parse_args()

    validator = ValidatorBase(args.protocol)
    index = 0
    for _ in range(1000):
        try:
            index += 1
            pdu: BaseLayer = validator.validate(args.packet, is_request=not args.response)
        except Exception as e:
            print(f"Validation failed: {index}", e)

    sys.exit(0)
