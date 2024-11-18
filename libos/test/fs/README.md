Test purpose
------------

These tests perform common FS operations in various ways to exercise the Gramine
FS subsystem:

- open/close
- read/write
- create/delete
- read/change size
- seek/tell
- memory-mapped read/write
- sendfile
- copy directory in different ways

How to execute
--------------

- `gramine-test pytest -v`

Encrypted file tests assume that Gramine was built with SGX enabled (see comment
in `test_enc.py`).

This test suite automatically creates files-under-test on startup and removes
them afterwards. When some test fails and you want to debug this failure, it's
more convenient to skip this automatic removal of files (and manually
investigate the test scenario, e.g. with the help of GDB). In such cases, use
the pytest option `--skip-teardown`.
