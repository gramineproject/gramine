#!/usr/bin/env python3

import unittest

from graminelibos.regression import (
    USES_MUSL,
    RegressionTestCase,
)

@unittest.skipIf(USES_MUSL, 'Assembly tests are disabled with musl')
class TC_00_X86_64(RegressionTestCase):
    def test_010_iret_emulation(self):
        self.run_binary(['asm/x86_64/iret_emulation'])
