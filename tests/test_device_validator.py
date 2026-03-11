"""Tests for _DeviceValidator socket crash recovery."""

from unittest.mock import MagicMock, patch

import pytest
from praetor.validator.device_validator import _DeviceValidator


class TestDeviceValidatorSocketCrashRecovery:
    """Tests for _DeviceValidator socket crash recovery in validate()."""

    def test_socket_error_on_send_triggers_reconnect(self) -> None:
        """When send raises OSError, reconnect() is called and OSError is re-raised."""
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = OSError("Connection reset")

        mock_protocol_info = MagicMock()
        mock_protocol_info.custom_port = 502
        mock_protocol_info.scapy_names = ["modbus"]

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
            patch(
                "praetor.validator.device_validator.ProtocolInfo.from_name",
                return_value=mock_protocol_info,
            ),
        ):
            validator = _DeviceValidator("mbtcp", lambda r: True)

            with pytest.raises(OSError):
                validator.validate("deadbeef")

            # close() was called once (during reconnect)
            mock_sock.close.assert_called_once()
            # The socket was reconnected after the crash
            assert mock_sock.connect.call_count == 2  # noqa: PLR2004

    def test_socket_error_on_receive_triggers_reconnect(self) -> None:
        """When receive raises OSError, reconnect() is called and OSError is re-raised."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("Broken pipe")

        mock_protocol_info = MagicMock()
        mock_protocol_info.custom_port = 502
        mock_protocol_info.scapy_names = ["modbus"]

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
            patch(
                "praetor.validator.device_validator.ProtocolInfo.from_name",
                return_value=mock_protocol_info,
            ),
        ):
            validator = _DeviceValidator("mbtcp", lambda r: True)

            with pytest.raises(OSError):
                validator.validate("deadbeef")

            mock_sock.close.assert_called_once()
            assert mock_sock.connect.call_count == 2  # noqa: PLR2004

    def test_no_reconnect_on_successful_send_receive(self) -> None:
        """When send/receive succeed, no reconnect is attempted."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00\x01"

        mock_protocol_info = MagicMock()
        mock_protocol_info.custom_port = 502
        mock_protocol_info.scapy_names = ["modbus"]

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
            patch(
                "praetor.validator.device_validator.ProtocolInfo.from_name",
                return_value=mock_protocol_info,
            ),
        ):
            validator = _DeviceValidator("mbtcp", lambda r: True)
            result = validator.validate("deadbeef")

        assert result == b"\x00\x01"
        mock_sock.close.assert_not_called()
        mock_sock.connect.assert_called_once()
