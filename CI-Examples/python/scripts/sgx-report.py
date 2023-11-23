#!/usr/bin/env python3

# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

import os
import sys

if not os.path.exists("/dev/attestation/report"):
    print("Cannot find `/dev/attestation/report`; are you running under SGX?")
    sys.exit(1)

with open("/dev/attestation/my_target_info", "rb") as f:
    my_target_info = f.read()

with open("/dev/attestation/target_info", "wb") as f:
    f.write(my_target_info)

with open("/dev/attestation/user_report_data", "wb") as f:
    f.write(b'\0'*64)

with open("/dev/attestation/report", "rb") as f:
    report = f.read()

print(f"Generated SGX report with size = {len(report)} and the following fields:")
print(f"  ATTRIBUTES.FLAGS: {report[48:56].hex()}  [ Debug bit: {report[48] & 2 > 0} ]")
print(f"  ATTRIBUTES.XFRM:  {report[56:64].hex()}")
print(f"  MRENCLAVE:        {report[64:96].hex()}")
print(f"  MRSIGNER:         {report[128:160].hex()}")
print(f"  ISVPRODID:        {report[256:258].hex()}")
print(f"  ISVSVN:           {report[258:260].hex()}")
print(f"  REPORTDATA:       {report[320:352].hex()}")
print(f"                    {report[352:384].hex()}")
