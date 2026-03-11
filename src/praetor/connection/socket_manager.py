"""Socket management utilities for Proteus.

This module provides a centralized socket manager to handle socket creation,
connection, reconnection, and cleanup operations.
"""

import logging
import socket
import time
import types
from threading import Thread
from typing import TYPE_CHECKING, Self, cast

from cursus.starter import Starter

if TYPE_CHECKING:
    from decima.logger import CustomLogger


class SocketManager:
    """Manages socket connections with automatic reconnection capabilities."""

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
        self._port: int = port
        self._timeout: float = timeout
        self._sock: socket.socket | None = None

        self._cursus = Starter(protocol, port=self._port, delay=3)
        self._server_thread: Thread = self._cursus.start_server()

        self._watchdog_thread = Thread(target=self._watchdog, daemon=True)
        self._watchdog_thread.start()

    def _watchdog(self) -> None:
        """Monitors the server thread and restarts it if it dies unexpectedly."""
        self._server_thread.join()

        self.logger.info(f"Server thread on port {self._port} died. Restarting...")
        time.sleep(1)  # Brief pause to avoid rapid-fire restart loops
        self._cursus.start_server()

    def connect(self) -> None:
        """Establish a socket connection to the target server."""
        if not self._is_server_running():
            self._cursus.start_server()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self._timeout)
        self._sock.connect((self._host, self._port))
        self.logger.debug(f"Connected to {self._host}:{self._port}")

    def _is_server_running(self) -> bool:
        """Check whether a process is listening on the configured host/port."""
        try:
            with socket.create_connection((self._host, self._port), timeout=self._timeout):
                return True
        except OSError:
            return False

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
        """Close the socket connection."""
        if self._sock:
            self._sock.close()
            self._sock = None
            self.logger.debug(f"Closed connection to {self._host}:{self._port}")

    def __enter__(self) -> Self:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: types.TracebackType | None) -> None:
        """Context manager exit."""
        self.close()
