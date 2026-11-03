from rhclient import Tunnel

import time
import base64
import concurrent.futures
import os
import socket
import gc
import weakref

import pytest

from conftest import eventually, exchange
from conftest import Echo, EchoServer


def test_forwards_tcp_over_authenticated_noise_and_stops(deployment):
    with Tunnel(**deployment.arguments()) as tunnel:
        assert tunnel.running
        assert eventually(lambda: exchange(deployment.public_port)) == b'hello through Noise'
    assert not tunnel.running
    tunnel.close()


def test_recovers_after_server_crash_without_recreating_client(deployment):
    with Tunnel(**deployment.arguments()) as tunnel:
        eventually(lambda: exchange(deployment.public_port))
        deployment.stop_server()
        with pytest.raises(OSError):
            exchange(deployment.public_port)
        assert tunnel.running
        deployment.start_server()
        eventually(lambda: exchange(deployment.public_port), timeout=15)
        deployment.stop_server()
        start = time.monotonic()
        tunnel.close()
        assert time.monotonic() - start < 2


@pytest.mark.parametrize(('field', 'value'), [
    ('server_addr', 'http://localhost:2333'),
    ('server_addr', '[not-ipv6]:2333'),
    ('server_addr', 'host..invalid:2333'),
    ('local_addr', 'localhost:0'),
    ('local_addr', 'localhost:65536'),
    ('service', ''),
    ('service', 'echo\n[server]'),
    ('token', ''),
    ('server_public_key', 'not-a-key'),
    ('heartbeat_timeout', 0),
    ('retry_interval', 0),
])
def test_rejects_invalid_configuration_without_echoing_secrets(deployment, field, value):
    arguments = {**deployment.arguments(), field: value}
    with pytest.raises(ValueError) as error:
        Tunnel(**arguments)
    assert deployment.token not in str(error.value)


@pytest.mark.parametrize('wrong_credential', ['token', 'server_public_key'])
def test_rejects_wrong_service_token_or_server_identity(deployment, wrong_credential):
    arguments = deployment.arguments()
    arguments[wrong_credential] = ('incorrect-service-token' if wrong_credential == 'token'
                                    else base64.b64encode(os.urandom(32)).decode())
    with Tunnel(**arguments) as tunnel:
        for _ in range(3):
            with pytest.raises(OSError):
                exchange(deployment.public_port)
            time.sleep(0.1)
        assert tunnel.running
    with Tunnel(**deployment.arguments()):
        eventually(lambda: exchange(deployment.public_port))


def test_transfers_binary_payloads_on_concurrent_connections(deployment):
    payload = bytes(range(256)) * 4096
    with Tunnel(**deployment.arguments()):
        eventually(lambda: exchange(deployment.public_port))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: exchange(deployment.public_port, payload, timeout=10), range(16)))
        assert all(result == payload for result in results)


def test_close_terminates_active_stream_and_is_thread_safe(deployment):
    tunnel = Tunnel(**deployment.arguments())
    try:
        eventually(lambda: exchange(deployment.public_port))
        with socket.create_connection(('127.0.0.1', deployment.public_port), timeout=1) as stream:
            stream.settimeout(2)
            stream.sendall(b'before close')
            assert stream.recv(100) == b'before close'
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: tunnel.close(), range(4)))
            try:
                assert stream.recv(100) == b''
            except ConnectionResetError:
                pass
        assert not tunnel.running
    finally:
        tunnel.close()


def test_configuration_is_private_and_removed_on_close(deployment, monkeypatch, tmp_path):
    temporary = tmp_path / 'native-temp'
    temporary.mkdir()
    monkeypatch.setenv('TMPDIR', str(temporary))
    with Tunnel(**deployment.arguments()):
        files = list(temporary.iterdir())
        assert len(files) == 1
        assert files[0].stat().st_mode & 0o777 == 0o600
        assert deployment.token in files[0].read_text()
        eventually(lambda: exchange(deployment.public_port))
    assert list(temporary.iterdir()) == []


def test_repeated_start_stop_releases_connections_and_configuration(deployment, monkeypatch, tmp_path):
    temporary = tmp_path / 'native-temp'
    temporary.mkdir()
    monkeypatch.setenv('TMPDIR', str(temporary))
    with Tunnel(**deployment.arguments()):
        eventually(lambda: exchange(deployment.public_port))
    descriptor_directory = '/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'
    initial_descriptors = len(os.listdir(descriptor_directory))
    for _ in range(12):
        with Tunnel(**deployment.arguments()):
            eventually(lambda: exchange(deployment.public_port))
        assert list(temporary.iterdir()) == []
        with pytest.raises(OSError):
            exchange(deployment.public_port)
    assert len(os.listdir(descriptor_directory)) <= initial_descriptors + 2


def test_garbage_collection_closes_an_abandoned_tunnel(deployment, monkeypatch, tmp_path):
    temporary = tmp_path / 'native-temp'
    temporary.mkdir()
    monkeypatch.setenv('TMPDIR', str(temporary))
    tunnel = Tunnel(**deployment.arguments())
    eventually(lambda: exchange(deployment.public_port))
    reference = weakref.ref(tunnel)
    del tunnel
    gc.collect()
    assert reference() is None
    assert list(temporary.iterdir()) == []
    with pytest.raises(OSError):
        exchange(deployment.public_port)


def test_context_closes_when_python_code_raises(deployment):
    with pytest.raises(KeyboardInterrupt):
        with Tunnel(**deployment.arguments()) as tunnel:
            eventually(lambda: exchange(deployment.public_port))
            raise KeyboardInterrupt
    assert not tunnel.running


@pytest.mark.parametrize('timeout', [-1, float('nan'), float('inf'), 301])
def test_invalid_close_deadline_does_not_stop_the_tunnel(deployment, timeout):
    with Tunnel(**deployment.arguments()) as tunnel:
        eventually(lambda: exchange(deployment.public_port))
        with pytest.raises(ValueError):
            tunnel.close(timeout)
        eventually(lambda: exchange(deployment.public_port))


def test_zero_close_deadline_can_be_retried(deployment):
    tunnel = Tunnel(**deployment.arguments())
    try:
        eventually(lambda: exchange(deployment.public_port))
        try:
            tunnel.close(timeout=0)
        except TimeoutError:
            pass
        tunnel.close()
        assert not tunnel.running
    finally:
        tunnel.close()


def test_starts_while_server_is_offline_then_connects(deployment):
    deployment.stop_server()
    start = time.monotonic()
    with Tunnel(**deployment.arguments()) as tunnel:
        assert time.monotonic() - start < 2
        assert tunnel.running
        deployment.start_server()
        eventually(lambda: exchange(deployment.public_port))


def test_close_cancels_an_incomplete_noise_handshake(deployment):
    with socket.socket() as blackhole:
        blackhole.bind(('127.0.0.1', 0))
        blackhole.listen()
        blackhole.settimeout(3)
        arguments = {**deployment.arguments(),
                     'server_addr': f'127.0.0.1:{blackhole.getsockname()[1]}'}
        tunnel = Tunnel(**arguments)
        try:
            connection, _ = blackhole.accept()
            with connection:
                start = time.monotonic()
                tunnel.close()
                assert time.monotonic() - start < 2
            assert not tunnel.running
        finally:
            tunnel.close()


def test_missing_temporary_directory_is_a_safe_startup_error(deployment, monkeypatch, tmp_path):
    monkeypatch.setenv('TMPDIR', str(tmp_path / 'missing'))
    with pytest.raises(RuntimeError) as error:
        Tunnel(**deployment.arguments())
    assert deployment.token not in str(error.value)


def test_backend_can_restart_without_recreating_tunnel(deployment):
    import threading

    with Tunnel(**deployment.arguments()):
        eventually(lambda: exchange(deployment.public_port))
        deployment.backend.shutdown()
        deployment.backend.server_close()
        deployment.thread.join(timeout=2)
        with pytest.raises(OSError):
            exchange(deployment.public_port)
        deployment.backend = EchoServer(('127.0.0.1', deployment.local_port), Echo)
        deployment.thread = threading.Thread(target=deployment.backend.serve_forever, daemon=True)
        deployment.thread.start()
        eventually(lambda: exchange(deployment.public_port))


def test_service_token_is_serialized_without_toml_injection(deployment):
    import json

    deployment.stop_server()
    token = 'quoted "token"\\with\nnewlines and unicode: \u2603'
    config = deployment.config.read_text().replace(json.dumps(deployment.token), json.dumps(token))
    deployment.config.write_text(config)
    deployment.token = token
    deployment.start_server()
    with Tunnel(**deployment.arguments()) as tunnel:
        assert token not in repr(tunnel)
        eventually(lambda: exchange(deployment.public_port))
