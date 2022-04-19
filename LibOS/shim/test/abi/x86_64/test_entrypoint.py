#!/usr/bin/env python3

from graminelibos.regression import RegressionTestCase

class TC_00_Entrypoint(RegressionTestCase):
    def test_000_atexit_func(self):
        self.run_binary(['atexit_func'])

    def test_000_fpu_control_word(self):
        self.run_binary(['fpu_control_word'])

    def test_000_rflags(self):
        self.run_binary(['rflags'])

    def test_000_mxcsr(self):
        self.run_binary(['mxcsr'])

    def test_000_stack(self):
        self.run_binary(['stack'])

    def test_000_arg(self):
        self.run_binary(['stack_arg', 'foo', 'bar'])
