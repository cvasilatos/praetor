"""Tests for proteus.utils.socket_manager."""

import socket
import types
from unittest.mock import MagicMock, patch

import pytest
from praetor.connection.socket_manager import SocketManager


@pytest.fixture(autouse=True)
def _mock_starter() -> types.GeneratorType:
    """Prevent tests from starting a real protocol server."""
    with patch("praetor.connection.socket_manager.Starter") as starter_cls:
        starter = starter_cls.return_value
        starter.wait_until_ready.return_value = True
        starter.start_server.return_value.is_alive.return_value = True
        yield starter


class TestSocketManagerConnect:
    """Tests for SocketManager.connect."""

    def test_init_waits_for_cursus_ready(self, _mock_starter: MagicMock) -> None:
        SocketManager("127.0.0.1", 502, "mbtcp")
        _mock_starter.wait_until_ready.assert_called_once_with(timeout=10.0)

    def test_connect_creates_socket(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ) as socket_ctor,
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            mgr.connect()
            socket_ctor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            mock_sock.connect.assert_called_once_with(("127.0.0.1", 502))
            mock_sock.settimeout.assert_called_once_with(0.01)

    def test_connect_uses_udp_socket_for_bacnet(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ) as socket_ctor,
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 47808, "bacnet")
            mgr.connect()

        socket_ctor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_sock.connect.assert_called_once_with(("127.0.0.1", 47808))

    def test_connect_waits_for_cursus_ready(self, _mock_starter: MagicMock) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            _mock_starter.wait_until_ready.reset_mock()

            mgr.connect()

            _mock_starter.wait_until_ready.assert_called_once_with(timeout=10.0)

    def test_connect_uses_custom_timeout(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp", timeout=5.0)
            mgr.connect()
            mock_sock.settimeout.assert_called_once_with(5.0)

    def test_connect_raises_when_cursus_never_reports_ready(
        self, _mock_starter: MagicMock
    ) -> None:
        _mock_starter.wait_until_ready.return_value = False

        with pytest.raises(TimeoutError, match="Timed out waiting for server"):
            SocketManager("127.0.0.1", 502, "mbtcp")


class TestSocketManagerSend:
    """Tests for SocketManager.send."""

    def test_send_calls_sendall(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            mgr.connect()
            mgr.send(b"\x01\x02")
            mock_sock.sendall.assert_called_once_with(b"\x01\x02")

    def test_send_uses_send_for_udp_protocols(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 47808, "bacnet")
            mgr.connect()
            mgr.send(b"\x01\x02")

        mock_sock.send.assert_called_once_with(b"\x01\x02")
        mock_sock.sendall.assert_not_called()

    def test_send_raises_when_not_connected(self) -> None:
        mgr = SocketManager("127.0.0.1", 502, "mbtcp")
        with pytest.raises(RuntimeError, match="Socket not connected"):
            mgr.send(b"\x01")


class TestSocketManagerReceive:
    """Tests for SocketManager.receive."""

    def test_receive_calls_recv(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xde\xad"
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            mgr.connect()
            result = mgr.receive(1024)
            mock_sock.recv.assert_called_once_with(1024)
            assert result == b"\xde\xad"

    def test_receive_raises_when_not_connected(self) -> None:
        mgr = SocketManager("127.0.0.1", 502, "mbtcp")
        with pytest.raises(RuntimeError, match="Socket not connected"):
            mgr.receive()


class TestSocketManagerClose:
    """Tests for SocketManager.close."""

    def test_close_closes_socket(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            mgr.connect()
            mgr.close()
            mock_sock.close.assert_called_once()
            assert mgr._sock is None

    def test_close_when_not_connected_is_noop(self) -> None:
        mgr = SocketManager("127.0.0.1", 502, "mbtcp")
        mgr.close()  # should not raise


class TestSocketManagerReconnect:
    """Tests for SocketManager.reconnect."""

    def test_reconnect_closes_and_reconnects(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            mgr = SocketManager("127.0.0.1", 502, "mbtcp")
            mgr.connect()
            mgr.reconnect()
            # close() + connect() = 2 connect calls total
            assert mock_sock.connect.call_count == 2  # noqa: PLR2004


class TestSocketManagerContextManager:
    """Tests for SocketManager as a context manager."""

    def test_context_manager_connects_and_closes(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            with SocketManager("127.0.0.1", 502, "mbtcp") as mgr:
                assert mgr._sock is mock_sock
            mock_sock.close.assert_called_once()

    def test_context_manager_closes_on_exception(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "praetor.connection.socket_manager.socket.socket",
                return_value=mock_sock,
            ),
            patch.object(SocketManager, "_is_server_running", return_value=True),
        ):
            with pytest.raises(RuntimeError):
                with SocketManager("127.0.0.1", 502, "mbtcp"):
                    raise RuntimeError("test error")
            mock_sock.close.assert_called_once()
