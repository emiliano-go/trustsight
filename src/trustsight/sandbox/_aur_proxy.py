"""The only egress the sandboxed git worker gets (A16).

The worker runs in a network namespace with no route off the machine.  For a
fetch it reaches a loopback listener in that namespace, which forwards bytes
to this proxy over one of a small pool of inherited Unix socketpairs.  This
proxy speaks HTTP ``CONNECT`` and accepts exactly one authority:
``aur.archlinux.org:443``.  The TLS session is end-to-end between libgit2 and
the AUR, so this process sees and interprets nothing beyond the CONNECT line.

The socketpairs are created here, before the worker is confined, and the
worker end is passed as an inherited descriptor.  After confinement the
worker's seccomp filter refuses ``socket(AF_UNIX)``, so code execution there
cannot open a new Unix socket to a host service; the only Unix sockets it
holds are these already-connected tunnels to this validator.
"""

from __future__ import annotations

import select
import socket
import threading

__all__ = ["AurFetchProxy"]

_AUR_HOST = "aur.archlinux.org"
_AUR_PORT = 443
_MAX_REQUEST_BYTES = 8192
_MAX_CONNECTIONS = 16
_CONNECT_TIMEOUT_SECONDS = 15
_RELAY_CHUNK = 65536

_FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
_UNAVAILABLE = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"


class AurFetchProxy:
    """A CONNECT proxy restricted to the AUR HTTPS endpoint.

    Each connection is a pre-created socketpair: the parent end is handled by
    a validator thread and the child end is inherited by the worker.  There
    is no filesystem socket path for a confined worker to rediscover, and no
    new Unix socket can be created on the worker side after seccomp.
    """

    def __init__(self, timeout: int = _CONNECT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout
        self._parent_sockets: list[socket.socket] = []
        self._child_sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stopping = threading.Event()
        try:
            for _ in range(_MAX_CONNECTIONS):
                parent, child = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_STREAM)
                self._parent_sockets.append(parent)
                self._child_sockets.append(child)
                thread = threading.Thread(
                    target=self._handle, args=(parent,), daemon=True)
                self._threads.append(thread)
                thread.start()
        except Exception:
            self.close()
            raise

    @property
    def child_fds(self) -> list[int]:
        return [child.fileno() for child in self._child_sockets]

    def release_child_fds(self) -> None:
        """Close the parent's copies after the worker inherited them."""
        for child in self._child_sockets:
            try:
                child.close()
            except OSError:
                pass
        self._child_sockets = []

    def close(self) -> None:
        self._stopping.set()
        self.release_child_fds()
        for parent in self._parent_sockets:
            try:
                parent.close()
            except OSError:
                pass
        self._parent_sockets = []
        for thread in self._threads:
            thread.join(timeout=1)
        self._threads = []

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self._timeout)
            authority = self._read_authority(connection)
            connection.settimeout(None)
            if authority != (_AUR_HOST, _AUR_PORT):
                try:
                    connection.sendall(_FORBIDDEN)
                except OSError:
                    pass
                return
            upstream = socket.create_connection(
                (_AUR_HOST, _AUR_PORT), timeout=self._timeout)
            try:
                connection.sendall(_ESTABLISHED)
                _relay(connection, upstream)
            finally:
                try:
                    upstream.close()
                except OSError:
                    pass
        except OSError:
            try:
                connection.sendall(_UNAVAILABLE)
            except OSError:
                pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    @staticmethod
    def _read_authority(connection: socket.socket):
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) >= _MAX_REQUEST_BYTES:
                return None
            try:
                chunk = connection.recv(1024)
            except OSError:
                return None
            if not chunk:
                return None
            data += chunk
        line = data.split(b"\r\n", 1)[0]
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            return None
        parts = text.split(" ")
        if len(parts) != 3 or parts[0] != "CONNECT":
            return None
        if not parts[2].startswith("HTTP/1."):
            return None
        authority = parts[1]
        if authority.count(":") != 1:
            return None
        host, port_text = authority.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return None
        return host, port


def _relay(left: socket.socket, right: socket.socket) -> None:
    try:
        while True:
            readable, _, _ = select.select([left, right], [], [], 0.2)
            for source in readable:
                target = right if source is left else left
                try:
                    chunk = source.recv(_RELAY_CHUNK)
                except OSError:
                    return
                if not chunk:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                try:
                    target.sendall(chunk)
                except OSError:
                    return
    finally:
        for sock in (left, right):
            try:
                sock.close()
            except OSError:
                pass
