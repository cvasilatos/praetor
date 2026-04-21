"""Basic sanity checks for the project."""

from praetor.protocol_info import ProtocolInfo


def test_protocol_info_lookup_sanity() -> None:
    """Ensure core protocol metadata lookup works."""
    info = ProtocolInfo.from_name("mbtcp")

    assert info is ProtocolInfo.MBTCP
    assert info.port == 502
    assert info.transport == "tcp"
    assert "modbus" in info.scapy_names


def test_protocol_info_lookup_for_bacnet_uses_udp() -> None:
    """Ensure BACnet metadata exposes UDP transport."""
    info = ProtocolInfo.from_name("bacnet")

    assert info is ProtocolInfo.BACNET
    assert info.transport == "udp"
