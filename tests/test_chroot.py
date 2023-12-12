import pytest
from graminelibos import manifest


# TODO: use tmp_path after deprecating *EL8
if tuple(int(i) for i in pytest.__version__.split('.')[:2]) < (3, 9):
    import pathlib
    @pytest.fixture
    def tmp_path(tmpdir):
        return pathlib.Path(tmpdir)

@pytest.fixture
def read_resolved_path(tmp_path):
    def read_resolved_path(path):
        inner_path = manifest.resolve_symlinks(path, chroot=tmp_path)
        outer_path = (tmp_path / inner_path.relative_to('/'))
        return outer_path.read_text()
    return read_resolved_path


def test_file_relative_symlink_1(tmp_path, read_resolved_path):
    (tmp_path / 'target').write_text('pass')
    (tmp_path / 'symlink').symlink_to('target')
    assert read_resolved_path('/symlink') == 'pass'

def test_file_relative_symlink_2(tmp_path, read_resolved_path):
    (tmp_path / 'subdir').mkdir()
    (tmp_path / 'subdir/target').write_text('pass')
    (tmp_path / 'subdir/symlink').symlink_to('target')
    assert read_resolved_path('/subdir/symlink') == 'pass'

def test_file_relative_symlink_3(tmp_path, read_resolved_path):
    (tmp_path / 'subdir').mkdir()
    (tmp_path / 'target').write_text('pass')
    (tmp_path / 'subdir/symlink').symlink_to('../target')
    assert read_resolved_path('/subdir/symlink') == 'pass'


def test_file_absolute_symlink_1(tmp_path, read_resolved_path):
    (tmp_path / 'target').write_text('pass')
    (tmp_path / 'symlink').symlink_to('/target')
    assert read_resolved_path('/symlink') == 'pass'

def test_file_absolute_symlink_2(tmp_path, read_resolved_path):
    (tmp_path / 'subdir').mkdir()
    (tmp_path / 'subdir/target').write_text('pass')
    (tmp_path / 'subdir/symlink').symlink_to('/subdir/target')
    assert read_resolved_path('/subdir/symlink') == 'pass'

def test_file_absolute_symlink_3(tmp_path, read_resolved_path):
    (tmp_path / 'subdir').mkdir()
    (tmp_path / 'target').write_text('pass')
    (tmp_path / 'subdir/symlink').symlink_to('/target')
    assert read_resolved_path('/subdir/symlink') == 'pass'


def test_directory_relative_symlink_1(tmp_path, read_resolved_path):
    (tmp_path / 'subdir').mkdir()
    (tmp_path / 'subdir/target').write_text('pass')
    (tmp_path / 'symlink').symlink_to('subdir')
    assert read_resolved_path('/symlink/target') == 'pass'


def test_bump_parent_against_root(tmp_path, read_resolved_path):
    (tmp_path / 'target').write_text('pass')
    (tmp_path / 'symlink').symlink_to('../../../target')

    assert read_resolved_path('/symlink') == 'pass'


def test_eloop_1(tmp_path):
    (tmp_path / 'symlink').symlink_to('symlink')
    with pytest.raises(OSError, match=r'\[Errno 40\] Too many levels of symbolic links'):
        manifest.resolve_symlinks('/symlink', chroot=tmp_path)

def test_eloop_2(tmp_path):
    (tmp_path / 'symlink').symlink_to('symlink')
    with pytest.raises(OSError, match=r'\[Errno 40\] Too many levels of symbolic links'):
        manifest.resolve_symlinks('/symlink/target', chroot=tmp_path)


def test_enotdir_1(tmp_path):
    (tmp_path / 'target').write_text('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/subdir', chroot=tmp_path)

@pytest.mark.xfail(
    reason='pathlib silently truncates trailing "/.", so "/target/." is equivalent to "/target"',
    strict=True,
)
def test_enotdir_2(tmp_path):
    (tmp_path / 'target').write_text('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/.', chroot=tmp_path)

def test_enotdir_3(tmp_path):
    (tmp_path / 'target').write_text('pass')
    with pytest.raises(NotADirectoryError):
        manifest.resolve_symlinks('/target/../target', chroot=tmp_path)
