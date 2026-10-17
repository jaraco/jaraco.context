import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from jaraco.context import tarball

if TYPE_CHECKING or sys.version_info >= (3, 12):
    import tarfile
else:
    from backports import tarfile


@pytest.mark.parametrize('filename', ['data.txt', 'nested/data.txt'])
def test_tarball_hardlinks(tmp_path: Path, filename: str) -> None:
    source = tmp_path / 'source'
    original = source / filename
    original.parent.mkdir(parents=True)
    original.write_text('hard-linked payload', encoding='utf-8')
    alias = source / 'alias.txt'
    os.link(original, alias)

    archive = tmp_path / 'hardlinks.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        tf.add(original, arcname=f'package/{filename}')
        tf.add(alias, arcname='package/alias.txt')
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        assert members[1].islnk()
        assert members[1].linkname == f'package/{filename}'

    target = tmp_path / 'extracted'
    with tarball(archive.as_uri(), target) as extracted:
        assert extracted == target
        assert (target / filename).read_text(encoding='utf-8') == 'hard-linked payload'
        assert (target / 'alias.txt').samefile(target / filename)
        assert not (target / 'package').exists()
    assert not target.exists()


@pytest.mark.parametrize(
    ('alias_path', 'linkname'),
    [('alias.txt', 'data.txt'), ('nested/alias.txt', '../data.txt')],
)
def test_tarball_relative_symlink(
    tmp_path: Path, alias_path: str, linkname: str
) -> None:
    source = tmp_path / 'source'
    source.mkdir()
    original = source / 'data.txt'
    original.write_text('symlink payload', encoding='utf-8')
    alias = source / 'alias.txt'
    alias.symlink_to(linkname)
    archive = tmp_path / 'symlink.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        tf.add(original, arcname='package/data.txt')
        tf.add(alias, arcname=f'package/{alias_path}')

    target = tmp_path / 'extracted'
    with tarball(archive.as_uri(), target):
        assert (target / alias_path).is_symlink()
        assert os.readlink(target / alias_path) == linkname
        assert (target / alias_path).read_text(encoding='utf-8') == 'symlink payload'
    assert not target.exists()


@pytest.mark.parametrize(
    ('linkname', 'error'),
    [
        ('package/../../outside.txt', tarfile.LinkOutsideDestinationError),
        ('package/../outside.txt', tarfile.LinkOutsideDestinationError),
        ('/package/data.txt', tarfile.AbsoluteLinkError),
    ],
)
def test_tarball_rejects_unsafe_hardlinks(
    tmp_path: Path, linkname: str, error: type[tarfile.FilterError]
) -> None:
    archive = tmp_path / 'unsafe.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        member = tarfile.TarInfo('package/alias.txt')
        member.type = tarfile.LNKTYPE
        member.linkname = linkname
        tf.addfile(member)

    target = tmp_path / 'extracted'
    with pytest.raises(error), tarball(archive.as_uri(), target):
        pytest.fail('unsafe hard link was extracted')
    assert not target.exists()
    assert not (tmp_path / 'outside.txt').exists()
