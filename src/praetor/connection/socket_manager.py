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
        self._port: int = port
        self._timeout: float = timeout
        self._sock: socket.socket | None = None

        self._configure_multiprocessing_start_method()

        self._cursus = Starter(protocol, port=self._port, delay=3)
        self._server_thread: Thread = self._cursus.start_server()
        self._wait_for_server_ready()

        self._watchdog_thread = Thread(target=self._watchdog, daemon=True)
        self._watchdog_thread.start()

        self._shutdown = False

    @staticmethod
    def _configure_multiprocessing_start_method() -> None:
        """Use fork on macOS to avoid pickling ctypes-backed server objects."""
        if platform.system() != "Darwin":
            return

        current_method = multiprocessing.get_start_method(allow_none=True)
        if current_method != "fork":
            multiprocessing.set_start_method("fork", force=True)

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

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        if self._shutdown:
            return
        self._shutdown = True

        self.close()
        try:
            self._cursus.stop_server()
        except Exception:
            self.logger.exception("Failed stopping managed server")

    def __enter__(self) -> Self:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: types.TracebackType | None) -> None:
        """Context manager exit."""
        self.close()
