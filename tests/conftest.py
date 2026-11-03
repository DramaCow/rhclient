import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import threading
import time

import pytest


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def eventually(action, timeout=10):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return action()
        except (OSError, AssertionError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def exchange(port, payload=b'hello through Noise', timeout=0.5):
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(payload)
        result = bytearray()
        while len(result) < len(payload):
            chunk = stream.recv(min(65536, len(payload) - len(result)))
            if not chunk:
                raise ConnectionError('Tunnel closed before completing the response')
            result.extend(chunk)
        assert bytes(result) == payload
        return bytes(result)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Deployment:
    def __init__(self, binary, directory, private, public):
        self.binary = binary
        self.directory = directory
        self.control_port = free_port()
        self.public_port = free_port()
        self.backend = EchoServer(('127.0.0.1', 0), Echo)
        self.local_port = self.backend.server_address[1]
        self.thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.thread.start()
        self.token = 'integration-only-service-token'
        self.public_key = public
        self.config = directory / 'server.toml'
        self.config.write_text(f'''
[server]
bind_addr = "127.0.0.1:{self.control_port}"
heartbeat_interval = 1
[server.transport]
type = "noise"
[server.transport.noise]
pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"
local_private_key = {json.dumps(private)}
[server.services.echo]
bind_addr = "127.0.0.1:{self.public_port}"
token = {json.dumps(self.token)}
''')
        self.config.chmod(0o600)
        self.process = None
        self.start_server()

    def arguments(self):
        return dict(server_addr=f'127.0.0.1:{self.control_port}',
                    local_addr=f'127.0.0.1:{self.local_port}', service='echo',
                    token=self.token, server_public_key=self.public_key,
                    heartbeat_timeout=3, retry_interval=1)

    def start_server(self):
        self.process = subprocess.Popen([self.binary, '--server', str(self.config)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def listening():
            assert self.process.poll() is None, 'Upstream Rathole server exited'
            with socket.create_connection(('127.0.0.1', self.control_port), timeout=0.2):
                pass

        eventually(listening)

    def stop_server(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def close(self):
        self.stop_server()
        self.backend.shutdown()
        self.backend.server_close()
        self.thread.join(timeout=2)


@pytest.fixture(scope='session')
def rathole_binary():
    binary = os.environ.get('RATHOLE_BIN')
    if not binary or not Path(binary).is_file():
        pytest.fail('Set RATHOLE_BIN to the upstream Rathole 0.5.0 executable')
    return str(Path(binary).resolve())


@pytest.fixture(scope='session')
def noise_keys(rathole_binary):
    output = subprocess.check_output([rathole_binary, '--genkey'], text=True)
    private = output.split('Private Key:\n', 1)[1].splitlines()[0]
    public = output.split('Public Key:\n', 1)[1].splitlines()[0]
    return private, public


@pytest.fixture
def deployment(rathole_binary, noise_keys, tmp_path):
    instance = Deployment(rathole_binary, tmp_path, *noise_keys)
    try:
        yield instance
    finally:
        instance.close()
