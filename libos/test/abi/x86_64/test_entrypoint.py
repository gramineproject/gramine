#!/usr/bin/env python3

import os
import subprocess

from graminelibos.regression import RegressionTestCase

class TC_00_Entrypoint(RegressionTestCase):
    def test_010_atexit_func(self):
        self.run_binary(['atexit_func'])

    def test_020_fpu_control_word(self):
        self.run_binary(['fpu_control_word'])

    def test_030_rflags(self):
        self.run_binary(['rflags'])

    def test_040_mxcsr(self):
        self.run_binary(['mxcsr'])

    def test_050_stack(self):
        self.run_binary(['stack'])

    def test_060_arg(self):
        args = ['stack_arg', 'foo', 'bar']
        result = subprocess.check_output(['gramine-argv-serializer'] + args)
        with open('stack_arg_argv_input', 'wb') as f:
            f.write(result)
        try:
            self.run_binary(['stack_arg'])
        finally:
            os.remove('stack_arg_argv_input')

    def test_070_env(self):
        self.run_binary(['stack_env'])

    def test_080_auxv(self):
        self.run_binary(['stack_auxiliary'])
