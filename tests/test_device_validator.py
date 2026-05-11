"""Tests for _DeviceValidator socket crash recovery."""

from unittest.mock import MagicMock, patch

import pytest
from praetor.protocol_info import ProtocolInfo
from praetor.validator.device_validator import _DeviceValidator


class TestDeviceValidatorSocketCrashRecovery:
    """Tests for _DeviceValidator socket crash recovery in validate()."""

    def test_socket_error_on_send_triggers_reconnect(self) -> None:
        """When send raises OSError, reconnect() is called and OSError is re-raised."""
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = OSError("Connection reset")

        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch("praetor.connection.socket_manager.Starter"),
            patch(
                "praetor.connection.socket_manager.SocketManager._is_server_running",
                return_value=True,
            ),
        ):
            validator = _DeviceValidator([ProtocolInfo.MBTCP], lambda r: True)

            with pytest.raises(OSError):
                validator.validate("deadbeef", protocol="mbtcp")

            # close() was called once (during reconnect)
            mock_sock.close.assert_called_once()
            # The socket was reconnected after the crash
            assert mock_sock.connect.call_count == 2  # noqa: PLR2004

    def test_socket_error_on_receive_triggers_reconnect(self) -> None:
        """When receive raises OSError, reconnect() is called and OSError is re-raised."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("Broken pipe")

        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch("praetor.connection.socket_manager.Starter"),
            patch(
                "praetor.connection.socket_manager.SocketManager._is_server_running",
                return_value=True,
            ),
        ):
            validator = _DeviceValidator([ProtocolInfo.MBTCP], lambda r: True)

            with pytest.raises(OSError):
                validator.validate("deadbeef", protocol="mbtcp")

            mock_sock.close.assert_called_once()
            assert mock_sock.connect.call_count == 2  # noqa: PLR2004

    def test_no_reconnect_on_successful_send_receive(self) -> None:
        """When send/receive succeed, no reconnect is attempted."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00\x01"

        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch("praetor.connection.socket_manager.Starter"),
            patch(
                "praetor.connection.socket_manager.SocketManager._is_server_running",
                return_value=True,
            ),
        ):
            validator = _DeviceValidator([ProtocolInfo.MBTCP], lambda r: True)
            result = validator.validate("deadbeef", protocol="mbtcp")

        assert result == b"\x00\x01"
        mock_sock.close.assert_not_called()
        mock_sock.connect.assert_called_once()


def test_multi_protocol_device_validator_uses_requested_protocol() -> None:
    """A multi-protocol device validator should validate only the requested protocol."""
    mbtcp_socket_manager = MagicMock()
    mbtcp_socket_manager.receive.return_value = b"\x01"
    s7comm_socket_manager = MagicMock()
    s7comm_socket_manager.receive.return_value = b"\x02"

    def mbtcp_response_validator(response_hex: str) -> bool:
        return response_hex == "ff"

    def s7comm_response_validator(response_hex: str) -> bool:
        return response_hex == "02"

    with patch(
        "praetor.validator.device_validator.SocketManager",
        side_effect=[mbtcp_socket_manager, s7comm_socket_manager],
    ) as socket_manager_cls:
        validator = _DeviceValidator(
            [ProtocolInfo.MBTCP, ProtocolInfo.S7COMM],
            {"mbtcp": mbtcp_response_validator, "s7comm": s7comm_response_validator},
        )

    result = validator.validate("deadbeef", protocol="s7comm")

    assert result == b"\x02"
    assert socket_manager_cls.call_count == 2  # noqa: PLR2004
    mbtcp_socket_manager.connect.assert_called_once()
    s7comm_socket_manager.connect.assert_called_once()
    mbtcp_socket_manager.send.assert_not_called()
    s7comm_socket_manager.send.assert_called_once_with(bytes.fromhex("deadbeef"))
