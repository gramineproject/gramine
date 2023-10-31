#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

import argparse
import functools
import os
import string

# NOTE: do not include the usual <invalid> group, since we don't want to
# fail on e-mail addresses in the header
class MesonTemplate(string.Template):
    pattern = '''
        @(?:
            (?P<escaped>@) |
            (?P<named>[A-Za-z0-9_]+)@ |
            (?P<braced>[A-Za-z0-9_]+)@
        )
    '''

_parser = argparse.ArgumentParser()
_parser.add_argument('-m', '--mode', metavar='MODE',
    type=functools.partial(int, base=8),
    help='set permission mode (as in chmod)',
)
_parser.add_argument('-f', '--config', metavar='PATH',
    action='append',
    type=argparse.FileType('r'),
    help='read file with KEY=VALUE defines (see -D), one per line'
)
_parser.add_argument('-D', '--define', metavar='KEY=VALUE',
    action='append',
    default=[],
    help='define a substitution for the template',
)
_parser.add_argument('infile', metavar='IN',
    nargs='?',
    type=argparse.FileType('r'),
    default='-',
    help='input file or "-" for stdin'
)
_parser.add_argument('outfile', metavar='OUT',
    type=argparse.FileType('w'),
    nargs='?',
    default='-',
    help='output file or "-" for stdout'
)

def main(args=None):
    args = _parser.parse_args(args)
    template = MesonTemplate(args.infile.read())
    substs = {}

    for file in args.config:
        for line in file:
            if line[0] in '\n#':
                continue
            k, v = line.rstrip('\n').split('=')
            substs[k] = v

    for value in args.define:
        try:
            k, v = value.split('=', 1)
        except ValueError:
            k, v = value, True
        substs[k] = v

    args.outfile.write(template.substitute(substs))
    args.outfile.flush()

    if args.mode is not None:
        if not os.path.exists(args.outfile.name):
            # it might not exist if it's "<stdout>"
            _parser.error('cannot set mode on pipe')
        os.chmod(args.outfile.name, args.mode)

if __name__ == '__main__':
    main()
