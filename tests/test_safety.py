import io
import tarfile
import types

import pytest

import jaraco.context


def make_tarball_with(member):
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode='w') as tar:
        tarinfo = tarfile.TarInfo(name=member.path)
        tarinfo.size = len(member.content)
        tar.addfile(tarinfo, io.BytesIO(member.content.encode('ascii')))

    tar_data.seek(0)
    return tar_data


cases = [
    # Legitimate file
    types.SimpleNamespace(
        path='dummy_dir/legitimate_file.txt',
        content='This file stays in target directory',
        name='legitimate',
    ),
    # Simple traversal to /tmp
    types.SimpleNamespace(
        path='dummy_dir/../../tmp/pwned_by_zipslip.txt',
        content='[ZIPSLIP] File written to /tmp via path traversal!',
        name='pwned_via_tmp',
    ),
    # Write to home directory
    types.SimpleNamespace(
        path='dummy_dir/../../../../home/pwned_home.txt',
        content='[ZIPSLIP] Attempted write to home directory',
        name='pwned_via_home',
    ),
    # current directory parent
    types.SimpleNamespace(
        path='dummy_dir/../escaped.txt',
        content='[ZIPSLIP] File in parent directory!',
        name='pwned_escaped',
    ),
]


@pytest.fixture(params=cases)
def tarfile_case(request):
    return tarfile.open(fileobj=make_tarball_with(request.param), mode='r')


def test_zipslip_exploit(tmp_path, tarfile_case):
    """
    Ensure that protections from the default tarfile filter are applied.
    """
    (member,) = tarfile_case
    processed_member = jaraco.context.strip_first_component(member, tmp_path)
    assert '..' not in processed_member.name
    # tarfile_case.extract(processed_member, path=tmp_path)
