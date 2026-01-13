import io
import sys
import types
from contextlib import nullcontext as does_not_raise

import pytest

import jaraco.context
from jaraco.context import tarfile


def make_tarball_with(member):
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode='w') as tar:
        tarinfo = tarfile.TarInfo(name=member.path)
        content = f'content for {member.path}'
        bin_content = content.encode('ascii')
        tarinfo.size = len(bin_content)
        tar.addfile(tarinfo, io.BytesIO(bin_content))

    tar_data.seek(0)
    return tar_data


cases = [
    types.SimpleNamespace(
        path='dummy_dir/legitimate_file.txt',
        expect=does_not_raise(),
    ),
    pytest.param(
        types.SimpleNamespace(
            path='dummy_dir/subdir/../legitimate_file.txt',
            expect=does_not_raise(),
        ),
        marks=pytest.mark.skipif(
            (3, 11) < sys.version_info < (3, 13),
            reason='Fails with FileExistsError on Python 3.12',
        ),
    ),
    types.SimpleNamespace(
        path='dummy_dir/../../tmp/pwned_by_zipslip.txt',
        expect=pytest.raises(tarfile.OutsideDestinationError),
    ),
    types.SimpleNamespace(
        path='dummy_dir/../../../../home/pwned_home.txt',
        expect=pytest.raises(tarfile.OutsideDestinationError),
    ),
    types.SimpleNamespace(
        path='dummy_dir/../escaped.txt',
        expect=pytest.raises(tarfile.OutsideDestinationError),
    ),
]


@pytest.fixture(params=cases)
def tarfile_case(request):
    with tarfile.open(fileobj=make_tarball_with(request.param), mode='r') as tf:
        yield types.SimpleNamespace(
            tarfile=tf,
            expect=request.param.expect,
        )


def test_zipslip_exploit(tmp_path, tarfile_case):
    """
    Ensure that protections from the default tarfile filter are applied.
    """
    (member,) = tarfile_case.tarfile
    with tarfile_case.expect:
        tarfile_case.tarfile.extract(
            member, path=tmp_path, filter=jaraco.context._default_filter
        )
