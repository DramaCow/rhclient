import weakref

from ._native import _Tunnel

__all__ = ["Tunnel"]


class Tunnel:

    def __init__(self, *, server_addr: str, local_addr: str, service: str,
                 token: str, server_public_key: str, heartbeat_timeout: int = 40,
                 retry_interval: int = 1):
        self._native = _Tunnel(server_addr, local_addr, service, token,
                               server_public_key, heartbeat_timeout, retry_interval)
        self._finalizer = weakref.finalize(self, self._native.close)

    @property
    def running(self) -> bool:
        return self._native.running

    def close(self, timeout: float = 5.0) -> None:
        self._native.close(timeout)
        self._finalizer.detach()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
