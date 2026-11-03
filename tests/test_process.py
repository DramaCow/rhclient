import json
import os
import selectors
import signal
import subprocess
import sys

import pytest

from conftest import eventually, exchange


CHILD = '''
import json, signal, sys, time
from rhclient import Tunnel
arguments = json.loads(sys.stdin.readline())
if sys.argv[1] == "exit":
    tunnel = Tunnel(**arguments)
    print("ready", flush=True)
    sys.stdin.readline()
else:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        with Tunnel(**arguments):
            print("ready", flush=True)
            while True:
                time.sleep(0.05)
    except KeyboardInterrupt:
        pass
'''


@pytest.mark.parametrize('mode', ['exit', 'interrupt', 'terminate'])
def test_python_shutdown_cleans_native_resources(deployment, tmp_path, mode):
    temporary = tmp_path / 'child-temp'
    temporary.mkdir()
    process = subprocess.Popen([sys.executable, '-c', CHILD, mode], text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               env={**os.environ, 'TMPDIR': str(temporary)})
    try:
        process.stdin.write(json.dumps(deployment.arguments()) + '\n')
        process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=5), 'Child did not initialise its tunnel'
            assert process.stdout.readline().strip() == 'ready'
        eventually(lambda: exchange(deployment.public_port))
        if mode == 'exit':
            process.stdin.write('finish\n')
            process.stdin.flush()
        else:
            process.send_signal(signal.SIGINT if mode == 'interrupt' else signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0
        assert deployment.token not in stdout + stderr
        assert list(temporary.iterdir()) == []
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
