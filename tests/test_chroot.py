# TODO write tests:
# - a/b/file/.. (should raise NotADirectoryError)
# - a/b/file/. (same)

import pytest
from graminelibos import manifest


# TODO: use tmp_path after deprecating .el8
if tuple(int(i) for i in pytest.__version__.split('.')[:2]) < (3, 9):
    import pathlib
    @pytest.fixture
    def tmp_path(tmpdir):
        return pathlib.Path(tmpdir)


def test_file_relative_symlink_1(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    (tmp_path / 'symlink').symlink_to('target')
    assert (tmp_path / manifest.resolve_symlinks('/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'

def test_file_relative_symlink_2(tmp_path):
    (tmp_path / 'subdir').mkdir()
    with open(tmp_path / 'subdir/target', 'w') as file:
        file.write('pass')
    (tmp_path / 'subdir/symlink').symlink_to('target')
    assert (tmp_path / manifest.resolve_symlinks('/subdir/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'

def test_file_relative_symlink_3(tmp_path):
    (tmp_path / 'subdir').mkdir()
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    (tmp_path / 'subdir/symlink').symlink_to('../target')
    assert (tmp_path / manifest.resolve_symlinks('/subdir/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'


def test_file_absolute_symlink_1(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    (tmp_path / 'symlink').symlink_to('/target')
    assert (tmp_path / manifest.resolve_symlinks('/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'

def test_file_absolute_symlink_2(tmp_path):
    (tmp_path / 'subdir').mkdir()
    with open(tmp_path / 'subdir/target', 'w') as file:
        file.write('pass')
    (tmp_path / 'subdir/symlink').symlink_to('/subdir/target')
    assert (tmp_path / manifest.resolve_symlinks('/subdir/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'

def test_file_absolute_symlink_3(tmp_path):
    (tmp_path / 'subdir').mkdir()
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    (tmp_path / 'subdir/symlink').symlink_to('/target')
    assert (tmp_path / manifest.resolve_symlinks('/subdir/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'


def test_directory_relative_symlink_1(tmp_path):
    (tmp_path / 'subdir').mkdir()
    with open(tmp_path / 'subdir/target', 'w') as file:
        file.write('pass')
    (tmp_path / 'symlink').symlink_to('subdir')
    assert (tmp_path / manifest.resolve_symlinks('/symlink/target', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'


def test_bump_parent_against_root(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    (tmp_path / 'symlink').symlink_to('../../../target')

    assert (tmp_path / manifest.resolve_symlinks('/symlink', chroot=tmp_path).relative_to('/')
        ).read_text() == 'pass'


def test_eloop_1(tmp_path):
    (tmp_path / 'symlink').symlink_to('symlink')
    with pytest.raises(OSError, match=r'\[Errno 40\] Too many levels of symbolic links'):
        manifest.resolve_symlinks('/symlink', chroot=tmp_path)

def test_eloop_2(tmp_path):
    (tmp_path / 'symlink').symlink_to('symlink')
    with pytest.raises(OSError, match=r'\[Errno 40\] Too many levels of symbolic links'):
        manifest.resolve_symlinks('/symlink/target', chroot=tmp_path)


def test_enotdir_1(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/subdir', chroot=tmp_path)

@pytest.mark.xfail(
    reason='pathlib silently truncates trailing /.", so /target/. is equivalent to /target')
def test_enotdir_2(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/.', chroot=tmp_path)

def test_enotdir_3(tmp_path):
    with open(tmp_path / 'target', 'w') as file:
        file.write('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/../target', chroot=tmp_path)
