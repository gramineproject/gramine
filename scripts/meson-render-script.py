#!/usr/bin/python3 -O
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2023 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

import os
import string

import click

class MesonTemplate(string.Template):
    pattern = '''
        @(?:
            (?P<escaped>@) |
            (?P<named>[A-Za-z0-9_]+)@ |
            (?P<braced>[A-Za-z0-9_]+)@ |
            (?P<invalid>)
        )
    '''

def validate_define(_ctx, _param, values):
    ret = {}
    for value in values:
        try:
            k, v = value.split('=', 1)
        except ValueError:
            k, v = value, True
        ret[k] = v
    return ret

def validate_mode(_ctx, _param, value):
    if value is None:
        return value
    return int(value, 8)

@click.command()
@click.option('--mode', '-m', callback=validate_mode)
@click.option('--config', '-f', multiple=True, type=click.File('r'))
@click.option('--define', '-D', multiple=True, callback=validate_define)
@click.argument('infile', type=click.File('r'), default='-')
@click.argument('outfile', type=click.File('w'), default='-')
@click.pass_context
def main(ctx, mode, config, define, infile, outfile):
    template = MesonTemplate(infile.read())
    substs = {}

    for file in config:
        for line in file:
            if line[0] in '\n#':
                continue
            k, v = line.rstrip('\n').split('=')
            substs[k] = v

    substs.update(define)

    outfile.write(template.safe_substitute(substs))
    outfile.flush()

    if mode is not None:
        if not os.path.exists(outfile.name):
            # it might not exist if it's "<stdout>"
            ctx.fail('cannot set mode on pipe')
        os.chmod(outfile.name, mode)

if __name__ == '__main__':
    main()
