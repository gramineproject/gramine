import gdb
import re

def adversary_do(cmd):
    # extract interesting info from context
    test_function=gdb.selected_frame().older().name()
    operation=gdb.selected_frame().name()
    internal_path=gdb.selected_frame().read_var('path').string()
    external_path=re.sub(r'/tmp/enc_input/', './tmp/enc_input/', internal_path)
    external_path_saved=external_path+"._saved_"
    try:
        internal_path2=gdb.selected_frame().read_var('path2').string()
        external_path2=re.sub(r'/tmp/enc_input/', './tmp/enc_input/', internal_path2)
        opt_arg=f",{internal_path2}"
    except ValueError:
        internal_path2=""
        external_path2=""
        opt_arg=""

    # execute and report result for pytest digestion
    try:
        cmd(external_path, external_path_saved, external_path2)
        print(f"OK: {test_function} in {operation}({internal_path}{opt_arg}])")
    except Exception as e:
        print(f"FAIL: {test_function} in {operation}({internal_path}{opt_arg}): {e}")
