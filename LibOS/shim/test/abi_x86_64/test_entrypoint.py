#!/usr/bin/env python3

from graminelibos.regression import (
    RegressionTestCase,
)

class TC_00_Entrypoint(RegressionTestCase):
    def test_000_atexit_func(self):
        self.run_binary(['atexit_func'], timeout=20)

    def test_000_fpu_control_word(self):
        self.run_binary(['fpu_control_word'], timeout=20)

    def test_000_rflags(self):
        self.run_binary(['rflags'], timeout=20)

    def test_000_mxcsr(self):
        self.run_binary(['mxcsr'], timeout=20)

    def test_000_stack(self):
        self.run_binary(['stack'], timeout=20)

    def test_000_argc_1(self):
        self.run_binary(['stack_argc1'], timeout=20)

    def test_000_argc_3(self):
        self.run_binary(['stack_argc3', 'foo', 'bar'], timeout=20)

    def test_000_argv_1(self):
        self.run_binary(['stack_argv1'], timeout=20)

    def test_000_argv_3(self):
        self.run_binary(['stack_argv3', 'foo', 'bar'], timeout=20)
