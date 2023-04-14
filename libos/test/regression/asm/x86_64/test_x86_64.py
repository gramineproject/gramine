#!/usr/bin/env python3

import unittest

from graminelibos.regression import (
    USES_MUSL,
    RegressionTestCase,
)

# These tests don't require libc, so it doesn't make sense to run them
# twice (once with glibc and once with musl) as the result is not dependable on libc.
@unittest.skipIf(USES_MUSL, 'Assembly tests are disabled with musl')
class TC_00_X86_64(RegressionTestCase):
    # The iret emulation is used only on PAL/Linux-SGX.
    # However, it doesn't hurt to run this test also on PAL/Linux to verify the test itself.
    def test_010_iret_emulation(self):
        self.run_binary(['asm/x86_64/iret_emulation'])
