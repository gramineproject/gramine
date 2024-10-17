import pytest

option = None

def pytest_addoption(parser):
    parser.addoption("--skip-teardown", action='store_true')

def pytest_configure(config):
    global option
    option = config.option
