import logging
from enum import Enum


class ProtocolInfo(Enum):
    MBTCP = ("mbtcp", 502, 5020, ["mbtcp", "modbus"])
    S7COMM = ("s7comm", 102, 1020, ["s7comm"])
    IEC104 = ("iec104", 2404, 24040, ["iec60870_104"])
    DNP3 = ("dnp3", 20000, 20000, ["dnp3"])
    ENIP = ("enip", 44818, 44818, ["enip"])
    BACNET = ("bacnet", 47808, 47808, ["bvlc", "bacnet", "bacapp"])
    HART_IP = ("hart", 5094, 5094, ["hart_ip"])
    ADS = ("ads", 48898, 48898, ["ams"])

    def __init__(self, name: str, port: int, custom_port: int, scapy_names: list[str]) -> None:
        logger_name = f"{self.__class__.__module__}.{self.__class__.__name__}"
        self.logger = logging.getLogger(logger_name)
        self._name = name
        self._port = port
        self._custom_port = custom_port
        self._scapy_names = scapy_names

    @property
    def protocol_name(self) -> str:
        return self._name
    @property
    def port(self) -> int:
        return self._port
    @property
    def custom_port(self) -> int:
        return self._custom_port
    @property
    def scapy_names(self) -> list[str]:
        return self._scapy_names

    @classmethod
    def from_name(cls, name: str) -> "ProtocolInfo":
        name_lower = name.lower()
        for member in cls:
            if member.protocol_name.lower() == name_lower or member.name.lower() == name_lower:
                return member
        raise ValueError(f"Unknown protocol name: {name}")
