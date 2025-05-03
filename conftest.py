from __future__ import annotations

import functools
import http.server
import io
import tarfile
import threading
from pathlib import Path
from typing import Generator

import portend
import pytest


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: object, *args: object) -> None:
        pass


@pytest.fixture
def tarfile_served(tmp_path_factory: pytest.TempPathFactory) -> Generator[str]:
    """
    Start an HTTP server serving a tarfile.
    """
    tmp_path = tmp_path_factory.mktemp('www')
    fn = tmp_path / 'served.tgz'
    tf = tarfile.open(fn, mode='w:gz')
    info = tarfile.TarInfo('served/contents.txt')
    tf.addfile(info, io.BytesIO('hello, contents'.encode()))
    tf.close()
    httpd, url = start_server(tmp_path)
    with httpd:
        yield url + '/served.tgz'


def start_server(path: Path) -> tuple[http.server.HTTPServer, str]:
    _host, port = addr = ('', portend.find_available_local_port())
    Handler = functools.partial(QuietHTTPRequestHandler, directory=path)  # type: ignore[arg-type] # python/typeshed#13477
    httpd = http.server.HTTPServer(addr, Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f'http://localhost:{port}'
