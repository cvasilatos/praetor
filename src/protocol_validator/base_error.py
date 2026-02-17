from scapy.packet import Packet


class BaseError(ValueError):
    def __init__(self, message: str, pdu: Packet, *, is_request: bool) -> None:
        super().__init__(message)
        self._pdu = pdu
        self._is_request = is_request

    @property
    def pdu(self) -> Packet:
        return self._pdu

    @property
    def is_request(self) -> bool:
        return self._is_request
