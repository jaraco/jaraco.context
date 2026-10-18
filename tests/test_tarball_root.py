import tarfile
from pathlib import Path

import jaraco.context


def test_tarball_accepts_a_root_directory_member(tmp_path: Path) -> None:
    root = tmp_path / 'package'
    root.mkdir()
    (root / 'contents.txt').write_text('archive contents', encoding='utf-8')
    archive = tmp_path / 'package.tar.gz'
    with tarfile.open(archive, mode='w:gz') as tf:
        tf.add(root, arcname='package')

    destination = tmp_path / 'extracted'
    with jaraco.context.tarball(archive.as_uri(), destination) as extracted:
        assert (
            Path(extracted, 'contents.txt').read_text(encoding='utf-8')
            == 'archive contents'
        )
        assert not Path(extracted, 'package').exists()
    assert not destination.exists()
