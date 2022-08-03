import os
import unittest

# Named import, so that Pytest does not pick up TC_00_FileSystem as belonging to this module.
import test_fs

# pylint: disable=too-many-public-methods
class TC_70_ShmFiles(test_fs.TC_00_FileSystem):
    @classmethod
    def setUpClass(cls):
        cls.FILE_SIZES = [0, 1, 2, 15, 16, 17, 255, 256, 257, 1023, 1024, 1025, 65535, 65536, 65537,
                          1048575, 1048576, 1048577]
        cls.TEST_DIR = 'tmp'
        cls.INDEXES = range(len(cls.FILE_SIZES))
        cls.INPUT_DIR = os.path.join(cls.TEST_DIR, 'input')
        cls.INPUT_FILES = [os.path.join(cls.INPUT_DIR, str(x)) for x in cls.FILE_SIZES]
        cls.OUTPUT_DIR = os.path.abspath('/dev/shm/test')
        cls.OUTPUT_FILES = [os.path.join(cls.OUTPUT_DIR, str(x)) for x in cls.FILE_SIZES]

        # create directory structure and test files
        os.mkdir(cls.TEST_DIR)
        os.mkdir(cls.INPUT_DIR)
        for i in cls.INDEXES:
            with open(cls.INPUT_FILES[i], 'wb') as file:
                file.write(os.urandom(cls.FILE_SIZES[i]))

    # This overrides parent class to remove @expectedFailureIf(HAS_SGX)
    def test_204_copy_dir_mmap_whole(self):
        self.do_copy_test('copy_mmap_whole', 30)

    # This overrides parent class to remove @expectedFailureIf(HAS_SGX)
    def test_205_copy_dir_mmap_seq(self):
        self.do_copy_test('copy_mmap_seq', 60)

    # This overrides parent class to remove @expectedFailureIf(HAS_SGX)
    def test_206_copy_dir_mmap_rev(self):
        self.do_copy_test('copy_mmap_rev', 60)

    @unittest.skip("not applicable for shm")
    def test_210_copy_dir_mounted(self):
        test_fs.TC_00_FileSystem.test_210_copy_dir_mounted(self)
