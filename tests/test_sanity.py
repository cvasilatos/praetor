"""Basic sanity checks for the project."""

import pytest

from praetor.protocol_info import (
    ProtocolInfo,
    normalize_protocol_infos,
    resolve_response_validator,
)


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


def test_normalize_protocol_infos_accepts_multiple_protocols() -> None:
    """Multiple protocol inputs should preserve order and de-duplicate aliases."""
    infos = normalize_protocol_infos(
        [ProtocolInfo.MBTCP, ProtocolInfo.MBTCP, ProtocolInfo.S7COMM]
    )

    assert infos == (ProtocolInfo.MBTCP, ProtocolInfo.S7COMM)


def test_normalize_protocol_infos_rejects_empty_sequences() -> None:
    """An empty protocol list is not a usable validator configuration."""
    with pytest.raises(ValueError, match="At least one protocol"):
        normalize_protocol_infos([])


def test_normalize_protocol_infos_rejects_string_sequences() -> None:
    """Constructor protocol configuration must use ProtocolInfo values."""
    with pytest.raises(TypeError, match="ProtocolInfo"):
        normalize_protocol_infos("mbtcp")  # type: ignore[arg-type]


def test_resolve_response_validator_uses_protocol_specific_mapping() -> None:
    """Response validator mappings should accept canonical protocol names."""

    def mbtcp_validator(response_hex: str) -> bool:
        return response_hex == "01"

    def s7comm_validator(response_hex: str) -> bool:
        return response_hex == "02"

    assert (
        resolve_response_validator(
            {"mbtcp": mbtcp_validator, "s7comm": s7comm_validator}, ProtocolInfo.S7COMM
        )
        is s7comm_validator
    )
