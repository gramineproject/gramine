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

In case some tests fail and you want to debug, there is a new
pytest option `--skip-teardown` which prevents the removal of generated test
files (in sub-directory `tmp`) and  allows to easily replicate and investigate 
manually the test scenarios, e.g., with help of `gdb`.
