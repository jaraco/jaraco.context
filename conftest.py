import http.server
import io
import functools
import tarfile
import threading

import portend
import pytest


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


@pytest.fixture
def tarfile_served(tmp_path_factory):
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


def start_server(path):
    _host, port = addr = ('', portend.find_available_local_port())
    Handler = functools.partial(QuietHTTPRequestHandler, directory=path)
    httpd = http.server.HTTPServer(addr, Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f'http://localhost:{port}'
