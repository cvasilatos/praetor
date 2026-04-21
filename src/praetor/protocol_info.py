"""Module for protocol information and supported protocols."""

import logging
from enum import Enum
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class ProtocolInfo(Enum):
    """Information about supported protocols."""

    MBTCP = ("mbtcp", 502, 5020, ["mbtcp", "modbus"], "tcp")
    S7COMM = ("s7comm", 102, 10200, ["s7comm"], "tcp")
    IEC104 = ("iec104", 2404, 24040, ["iec60870_104"], "tcp")
    DNP3 = ("dnp3", 20000, 20000, ["dnp3"], "tcp")
    ENIP = ("enip", 44818, 44818, ["enip"], "tcp")
    BACNET = ("bacnet", 47808, 47808, ["bvlc", "bacnet", "bacapp"], "udp")
    HART_IP = ("hart", 5094, 5094, ["hart_ip"], "tcp")
    ADS = ("ads", 48898, 48898, ["ams"], "tcp")

    def __init__(self, name: str, port: int, custom_port: int, scapy_names: list[str], transport: str) -> None:
        """Initialize ProtocolInfo enum member."""
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._name: str = name
        self._port: int = port
        self._custom_port: int = custom_port
        self._scapy_names: list[str] = scapy_names
        self._transport: str = transport

    @property
    def protocol_name(self) -> str:
        """Return the protocol name."""
        return self._name

    @property
    def port(self) -> int:
        """Return the default port, used for the validation through wireshark."""
        return self._port

    @property
    def custom_port(self) -> int:
        """Return the custom port for communicating with the server."""
        return self._custom_port

    @property
    def scapy_names(self) -> list[str]:
        """Return the list of scapy layer names associated with this protocol."""
        return self._scapy_names

    @property
    def transport(self) -> str:
        """Return the transport protocol used by the emulator connection."""
        return self._transport

    @classmethod
    def from_name(cls, name: str) -> "ProtocolInfo":
        """Get ProtocolInfo enum member by protocol name (case-insensitive)."""
        name_lower = name.lower()
        for member in cls:
            if member.protocol_name.lower() == name_lower or member.name.lower() == name_lower:
                return member
        raise ValueError(f"Unknown protocol name: {name}")
