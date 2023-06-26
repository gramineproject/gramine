#!/usr/bin/env python3

import argparse
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS

argparser = argparse.ArgumentParser()
argparser.add_argument('infile', type=argparse.FileType('rb'))

args = argparser.parse_args()

elf = ELFFile(args.infile)
for i, segment in enumerate(elf.iter_segments()):
    if segment.header.p_flags & P_FLAGS.PF_X and segment.header.p_flags & P_FLAGS.PF_W:
        print(f"error: segment {i} is both writable and executable")
        sys.exit(1)
