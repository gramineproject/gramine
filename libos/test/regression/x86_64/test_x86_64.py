#!/usr/bin/env python3

from graminelibos.regression import RegressionTestCase

class TC_00_X86_64(RegressionTestCase):
    def test_010_iret_emulation(self):
        self.run_binary(['iret_emulation'])
