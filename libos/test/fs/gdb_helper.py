import gdb
import re
import shutil

def adversary_do(cmd):
    # extract interesting info from context
    test_function=gdb.selected_frame().older().name()
    operation=gdb.selected_frame().name()
    internal_path=gdb.selected_frame().read_var('path').string()
    external_path=re.sub(r'/tmp/enc_input/', './tmp/enc_input/', internal_path)
    external_path_saved=external_path+"._saved_"

    # execute and report result for pytest digestion
    try:
        cmd(external_path, external_path_saved)
        print(f"OK: {test_function} in {operation}({internal_path})")
    except:
        print(f"FAIL: {test_function} in {operation}({internal_path})")
