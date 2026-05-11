"""Socket management utilities for Proteus.

This module provides a centralized socket manager to handle socket creation,
connection, reconnection, and cleanup operations.
"""

import logging
import multiprocessing
import platform
import socket
import time
import types
from threading import Thread
from typing import TYPE_CHECKING, Self, cast

from cursus.starter import Starter

from praetor.protocol_info import ProtocolInfo

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class SocketManager:
    """Manages socket connections with automatic reconnection capabilities."""

    _SERVER_STARTUP_TIMEOUT = 10.0

    def __init__(self, host: str, port: int, protocol: str, timeout: float = 0.01) -> None:
        """Initialize the SocketManager with connection parameters.

        Args:
            host: Target host address
            port: Target port number
            protocol: Protocol server startup preset for cursus
            timeout: Socket timeout in seconds
        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))
        self._host: str = host
        self._timeout: float = timeout
        self._sock: socket.socket | None = None
        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._transport: str = self._protocol_info.transport
        self._port: int = self._next_available_port(port)

        self._configure_multiprocessing_start_method()

        self._cursus = Starter(self._protocol_info.protocol_name, port=self._port, delay=3)
        self._server_thread: Thread = self._cursus.start_server()
        self._wait_for_server_ready()

        self._watchdog_thread = Thread(target=self._watchdog, daemon=True)
        self._watchdog_thread.start()

    @staticmethod
    def _configure_multiprocessing_start_method() -> None:
        """Use fork on macOS to avoid pickling ctypes-backed server objects."""
        if platform.system() != "Darwin":
            return

        current_method = multiprocessing.get_start_method(allow_none=True)
        if current_method != "fork":
            multiprocessing.set_start_method("fork", force=True)

    def _next_available_port(self, port: int) -> int:
        """Return the first available port at or after the requested port."""
        candidate_port = port
        while candidate_port <= 65535:  # noqa: PLR2004
            if self._is_port_available(candidate_port):
                if candidate_port != port:
                    self.logger.info(f"Port {port} is occupied. Using {candidate_port} for {self._protocol_info.protocol_name}.")
                return candidate_port
            candidate_port += 1

        raise RuntimeError(f"No available port found for {self._protocol_info.protocol_name} starting from {port}")

    def _is_port_available(self, port: int) -> bool:
        """Return whether cursus can bind the configured host/transport port."""
        sock_type = socket.SOCK_DGRAM if self._transport == "udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            try:
                sock.bind((self._host, port))
            except OSError:
                return False
        return True

    def _watchdog(self) -> None:
        """Monitors the server thread."""
        self.logger.debug(f"Monitoring server thread: {self._server_thread.name}")
        self._server_thread.join()
        time.sleep(5)  # Make sure the port is fully released before restarting

    def connect(self) -> None:
        """Establish a socket connection to the target server."""
        if not self._is_server_running():
            self.logger.info(f"Server on {self._host}:{self._port} not running. Starting server...")
            self._server_thread: Thread = self._cursus.start_server()
            self._wait_for_server_ready()
        else:
            self._wait_for_server_ready()

        sock_type = socket.SOCK_DGRAM if self._transport == "udp" else socket.SOCK_STREAM
        self._sock = socket.socket(socket.AF_INET, sock_type)
        self._sock.settimeout(self._timeout)
        self._sock.connect((self._host, self._port))
        self.logger.debug(f"Connected to {self._host}:{self._port}")

    def _is_server_running(self) -> bool:
        """Check whether the managed server thread is alive."""
        is_running = self._server_thread.is_alive()
        if is_running:
            self.logger.debug(f"Server thread is running for {self._host}:{self._port}")
        else:
            self.logger.debug(f"Server thread is not running for {self._host}:{self._port}")
        return is_running

    def _wait_for_server_ready(self) -> None:
        """Block until cursus reports that the managed server is ready."""
        if self._cursus.wait_until_ready(timeout=self._SERVER_STARTUP_TIMEOUT):
            return

        raise TimeoutError(f"Timed out waiting for server on {self._host}:{self._port} to become ready")

    def reconnect(self) -> None:
        """Close existing connection and establish a new one."""
        self.close()
        self.connect()
        self.logger.debug(f"Reconnected to {self._host}:{self._port}")

    def send(self, data: bytes) -> None:
        """Send data through the socket.

        Args:
            data: Bytes to send

        Raises:
            RuntimeError: If socket is not connected

        """
        if self._sock is None:
            raise RuntimeError("Socket not connected. Call connect() first.")
        if self._transport == "udp":
            self._sock.send(data)
            return
        self._sock.sendall(data)

    def receive(self, buffer_size: int = 4096) -> bytes:
        """Receive data from the socket.

        Args:
            buffer_size: Maximum bytes to receive

        Returns:
            Received bytes

        Raises:
            RuntimeError: If socket is not connected

        """
        if self._sock is None:
            raise RuntimeError("Socket not connected. Call connect() first.")
        return self._sock.recv(buffer_size)

    def close(self) -> None:
        """Close the client socket connection."""
        if self._sock:
            self._sock.close()
            self._sock = None
            self.logger.debug(f"Closed connection to {self._host}:{self._port}")

    def shutdown(self) -> None:
        """Close the client socket and stop the managed cursus server."""
        try:
            self._cursus.stop_server()
        except Exception:
            self.logger.exception("Failed stopping managed server")
        self.close()

    def __enter__(self) -> Self:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: types.TracebackType | None) -> None:
        """Context manager exit."""
        self.close()
