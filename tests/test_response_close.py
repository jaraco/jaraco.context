import io
import urllib.request
from pathlib import Path

import pytest

import jaraco.context
from jaraco.context import tarfile  # type: ignore[attr-defined]


def test_tarball_closes_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    response = io.BytesIO()
    with tarfile.open(fileobj=response, mode='w') as archive:
        member = tarfile.TarInfo('root/content.txt')
        member.size = 7
        archive.addfile(member, io.BytesIO(b'content'))
    response.seek(0)
    monkeypatch.setattr(urllib.request, 'urlopen', lambda url: response)
    target = tmp_path / 'extracted'
    with jaraco.context.tarball('https://example.invalid/archive.tar', target):
        assert (target / 'content.txt').read_bytes() == b'content'
    assert response.closed
    assert not target.exists()


def test_tarball_closes_response_when_archive_is_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    response = io.BytesIO(b'not a tar archive')
    monkeypatch.setattr(urllib.request, 'urlopen', lambda url: response)
    target = tmp_path / 'extracted'
    with (
        pytest.raises(tarfile.ReadError),
        jaraco.context.tarball('https://example.invalid/archive.tar', target),
    ):
        pytest.fail('invalid archive should not yield')
    assert response.closed
    assert not target.exists()
