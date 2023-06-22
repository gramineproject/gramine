from graminelibos.gen_jinja_env import parse_ldd

def test_parse_ldd():
    output = parse_ldd(
        # collected with glibc 2.31-0ubuntu9.9 on a helloworld app
        '''\
\tlinux-vdso.so.1 (0x00007ffd56342000)
\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3a87190000)
\t/lib64/ld-linux-x86-64.so.2 (0x00007f3a8738c000)
''')
    assert output == ['/lib/x86_64-linux-gnu/libc.so.6']

def test_parse_ldd_multiple_binaries():
    output = parse_ldd(
        # collected with glibc 2.36-9+deb12u3
        '''\
/usr/bin/cat:
\tlinux-vdso.so.1 (0x00007ffe71bfe000)
\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa5165ff000)
\t/lib64/ld-linux-x86-64.so.2 (0x00007fa5167f8000)
/usr/bin/echo:
\tlinux-vdso.so.1 (0x00007fff8fde5000)
\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7533ee1000)
\t/lib64/ld-linux-x86-64.so.2 (0x00007f75340da000)
''')
    assert output == ['/lib/x86_64-linux-gnu/libc.so.6']
