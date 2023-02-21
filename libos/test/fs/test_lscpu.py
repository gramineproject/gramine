from graminelibos.regression import (
    RegressionTestCase,
)
# pylint: disable=too-many-public-methods
class TC_11_Lscpu(RegressionTestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        pass

    
    def test_211_copy_lscpu_test(self):
        stdout, stderr = self.run_binary(['lscpu-test'])
        self.assertIn('lscpu-test test passed', stdout)
