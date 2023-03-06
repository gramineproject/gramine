#!/usr/bin/env python3

import unittest

from graminelibos.regression import (
    USES_MUSL,
    RegressionTestCase,
)

class TC_00_X86_64(RegressionTestCase):
    @unittest.skipIf(USES_MUSL, 'Assembly tests are disable with musl')
    def test_010_iret_emulation(self):
        self.run_binary(['asm/x86_64/iret_emulation'])
