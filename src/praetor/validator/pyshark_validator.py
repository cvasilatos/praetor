"""Module for the base class of protocol validation using Cursusd and Wireshark."""

import asyncio
import logging
import os
import secrets
import threading
from contextlib import suppress
from dataclasses import dataclass
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
from praetor.protocol_info import ProtocolInfo, normalize_protocol_infos, protocol_names


@dataclass
class _TcpState:
    """TCP sequence state for one configured protocol."""

    seq: int = 0
    ack: int = 0
    next_seq: int = 1
    next_ack: int = 1


class _PysharkValidator:
    """Base class for protocol validation using Cursusd and Wireshark."""

    def __init__(self, protocols: list[ProtocolInfo], *, event_loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Initialize the ValidatorBase with the specified protocols."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self._protocol_infos: tuple[ProtocolInfo, ...] = normalize_protocol_infos(protocols)
        self._protocol_names: tuple[str, ...] = protocol_names(self._protocol_infos)
        self.protocol: str = self._protocol_names[0]
        self.protocols: tuple[str, ...] = self._protocol_names
        self._protocol_info: ProtocolInfo = self._protocol_infos[0]
        self.scapy_names: list[str] = self._protocol_info.scapy_names
        self._owns_event_loop = False

        override_prefs: dict[str, str] = {}
        for protocol_info in self._protocol_infos:
            if protocol_info.protocol_name == "mbtcp":
                override_prefs["mbtcp.tcp.port"] = str(protocol_info.port)
                break

        resolved_event_loop = event_loop or self._resolve_event_loop()
        capture_kwargs: dict[str, object] = {
            "override_prefs": override_prefs,
            "custom_parameters": {"-o": "tcp.analyze_sequence_numbers:FALSE"},
            "eventloop": resolved_event_loop,
        }

        self._cap: pyshark.InMemCapture | None = pyshark.InMemCapture(**capture_kwargs)

        self._tcp_seq: int = 0
        self._tcp_ack: int = 0
        self._next_tcp_seq: int = 1
        self._next_tcp_ack: int = 1
        self._tcp_states: dict[str, _TcpState] = {protocol_info.protocol_name: _TcpState() for protocol_info in self._protocol_infos}

    def _resolve_event_loop(self) -> asyncio.AbstractEventLoop:
        """Reuse the active loop or create a private one for synchronous callers."""
        with suppress(RuntimeError):
            return asyncio.get_running_loop()

        with suppress(RuntimeError):
            return asyncio.get_event_loop()

        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        self._owns_event_loop = True

        if os.name == "posix" and threading.current_thread() is threading.main_thread() and hasattr(asyncio, "SafeChildWatcher"):
            with suppress(Exception):
                asyncio.set_child_watcher(asyncio.SafeChildWatcher())
                asyncio.get_child_watcher().attach_loop(event_loop)

        return event_loop

    async def _close_capture_async(self, capture: pyshark.InMemCapture) -> None:
        """Release tshark subprocess state without waiting forever on pyshark tasks."""
        running_processes = getattr(capture, "_running_processes", None)
        cleanup_subprocess = getattr(capture, "_cleanup_subprocess", None)
        if running_processes is not None and callable(cleanup_subprocess):
            for process in tuple(running_processes):
                with suppress(Exception):
                    await asyncio.wait_for(cleanup_subprocess(process), timeout=1.0)
            running_processes.clear()

        stderr_tasks = [task for task in getattr(capture, "_stderr_handling_tasks", []) if not task.done()]
        for task in stderr_tasks:
            task.cancel()
        if stderr_tasks:
            await asyncio.gather(*stderr_tasks, return_exceptions=True)
        with suppress(Exception):
            getattr(capture, "_stderr_handling_tasks", []).clear()

    def close(self) -> None:
        """Release the underlying pyshark capture."""
        capture = self._cap
        if capture is None:
            return

        event_loop = getattr(capture, "eventloop", None)
        if isinstance(event_loop, asyncio.AbstractEventLoop) and not event_loop.is_closed() and not event_loop.is_running():
            with suppress(Exception):
                event_loop.run_until_complete(self._close_capture_async(capture))
        else:
            with suppress(Exception):
                capture.close()

        self._cap = None

        if self._owns_event_loop and isinstance(event_loop, asyncio.AbstractEventLoop) and not event_loop.is_closed():
            with suppress(Exception):
                current_event_loop = asyncio.get_event_loop()
                if current_event_loop is event_loop:
                    asyncio.set_event_loop(None)
            with suppress(Exception):
                event_loop.close()

    def __del__(self) -> None:
        """Clean up resources when the ValidatorBase instance is destroyed."""
        with suppress(Exception):
            self.close()

    def _selected_protocol_info(self, protocol: str) -> ProtocolInfo:
        """Return the protocol metadata selected for validation."""
        requested_protocol = ProtocolInfo.from_name(protocol)
        if requested_protocol not in self._protocol_infos:
            raise ValueError(f"Protocol is not configured for this validator: {protocol}")
        return requested_protocol

    def validate(self, packet: str, *, is_request: bool, protocol: str) -> BaseLayer:
        """Validate the given packet bytes (in hex) as either a request or response.

        Args:
            packet: str - The packet bytes in hexadecimal string format.
            is_request: bool - Whether to treat the packet as a request (True) or response (False).
            protocol: Configured protocol name to validate against.

        Returns:
            BaseLayer - The protocol-specific layer if validation is successful.

        Raises:
            ValidatorWiresharkError: If Wireshark parsing detects an error in the packet.
            ValidatorError: If the expected protocol layer is not found in the parsed packet.

        Description:
            This method constructs a full Ethernet/IP/TCP or Ethernet/IP/UDP packet with the given payload, parses it using pyshark, and checks for protocol-specific
            layers and Wireshark expert info.

        """
        protocol_info = self._selected_protocol_info(protocol)
        return self._validate_protocol(packet, is_request=is_request, protocol_info=protocol_info)

    def _transport_layer(self, protocol_info: ProtocolInfo, *, is_request: bool, seq: int, ack: int) -> TCP | UDP:
        """Build the transport layer for a protocol validation attempt."""
        if protocol_info.transport == "udp":
            return UDP(sport=protocol_info.port, dport=protocol_info.port)
        if is_request:
            return TCP(sport=secrets.randbelow(65535 - 1024 + 1) + 1024, dport=protocol_info.port, flags="PA", seq=seq, ack=ack)
        return TCP(sport=protocol_info.port, dport=secrets.randbelow(65535 - 1024 + 1) + 1024, flags="PA", seq=seq, ack=ack)

    def _validate_protocol(self, packet: str, *, is_request: bool, protocol_info: ProtocolInfo) -> BaseLayer:
        """Validate the packet against one configured protocol."""
        payload_bytes: bytes = bytes.fromhex(packet)
        payload_len: int = len(payload_bytes)

        tcp_state = self._tcp_states[protocol_info.protocol_name]
        seq: int = tcp_state.seq
        ack: int = tcp_state.ack

        step: int = max(1, payload_len)
        next_seq: int = (seq + step) % (2**32)
        next_ack: int = (ack + step) % (2**32)

        tcp_layer = self._transport_layer(protocol_info, is_request=is_request, seq=seq, ack=ack)

        if self._cap is None:
            raise RuntimeError("Pyshark validator is closed.")

        full_packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.10", dst="192.168.1.20") / tcp_layer / Raw(load=payload_bytes)

        parsed_packet: Packet = self._cap.parse_packet(bytes(full_packet))
        self._cap.clear()

        self.logger.debug(f"Validating packet: {packet}, is_request={is_request}: {bytes(full_packet).hex()}")
        layer: BaseLayer
        for layer in parsed_packet.layers:
            if layer.layer_name not in {"tcp", "udp", "eth", "ip"}:
                self.logger.debug(f"Validate protocol related layer (is_request={is_request}): {layer}")

        temp_layer: BaseLayer
        for temp_layer in parsed_packet.layers:
            if temp_layer.get_field("_ws_expert"):
                error_msg: str = temp_layer.get_field("_ws_expert_message")
                error_group: str = temp_layer.get_field("_ws_group")
                error_severity: str = temp_layer.get_field("_ws_severity")
                raise ValidatorWiresharkError(f"Validation failed, Error: {error_msg} (Group: {error_group}, Severity: {error_severity})", parsed_packet, is_request=is_request)

        layer_names: list[str] = [layer.layer_name for layer in cast("list[BaseLayer]", parsed_packet.layers)]
        is_contained: bool = set(protocol_info.scapy_names).issubset(set(layer_names))
        if not is_contained:
            raise ValidatorError(f"Validation failed, no layer '{protocol_info.scapy_names}'", parsed_packet, is_request=is_request)

        tcp_state.seq = next_seq
        tcp_state.ack = next_ack
        tcp_state.next_seq = next_seq
        tcp_state.next_ack = next_ack
        if protocol_info is self._protocol_info:
            self._tcp_seq = next_seq
            self._tcp_ack = next_ack
            self._next_tcp_seq = next_seq
            self._next_tcp_ack = next_ack

        self.logger.trace(f"Validation successful for packet {is_request}: {parsed_packet}")

        return parsed_packet
