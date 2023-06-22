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
