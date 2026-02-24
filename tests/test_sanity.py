"""Basic sanity checks for the project."""

from praetor.protocol_info import ProtocolInfo


def test_protocol_info_lookup_sanity() -> None:
    """Ensure core protocol metadata lookup works."""
    info = ProtocolInfo.from_name("mbtcp")

    assert info is ProtocolInfo.MBTCP
    assert info.port == 502
    assert "modbus" in info.scapy_names
