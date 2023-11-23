#!/usr/bin/env python3

# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

import os
import sys

if not os.path.exists("/dev/attestation/quote"):
    print("Cannot find `/dev/attestation/quote`; "
          "are you running under SGX, with remote attestation enabled?")
    sys.exit(1)

with open('/dev/attestation/attestation_type') as f:
    print(f"Detected attestation type: {f.read()}")

with open("/dev/attestation/user_report_data", "wb") as f:
    f.write(b'\0'*64)

with open("/dev/attestation/quote", "rb") as f:
    quote = f.read()

print(f"Extracted SGX quote with size = {len(quote)} and the following fields:")
print(f"  ATTRIBUTES.FLAGS: {quote[96:104].hex()}  [ Debug bit: {quote[96] & 2 > 0} ]")
print(f"  ATTRIBUTES.XFRM:  {quote[104:112].hex()}")
print(f"  MRENCLAVE:        {quote[112:144].hex()}")
print(f"  MRSIGNER:         {quote[176:208].hex()}")
print(f"  ISVPRODID:        {quote[304:306].hex()}")
print(f"  ISVSVN:           {quote[306:308].hex()}")
print(f"  REPORTDATA:       {quote[368:400].hex()}")
print(f"                    {quote[400:432].hex()}")
