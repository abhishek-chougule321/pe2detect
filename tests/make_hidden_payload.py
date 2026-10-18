"""Recreate the CVE-2013-3900 / 3CX technique on a signed file for testing.

Appends bytes INSIDE the certificate table, after the PKCS#7 signature, and
updates the two length fields. The Authenticode hash does not cover these
bytes, so the signature still "matches", which PE2Detect must flag.
Usage: python make_hidden_payload.py <signed-input> <output>
"""
import struct, sys

data = bytearray(open(sys.argv[1], "rb").read())
pe = struct.unpack_from("<I", data, 0x3C)[0]
opt = pe + 24
dirs = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
sec_entry = dirs + 4 * 8                       # data directory #4: the certificate table
offset, size = struct.unpack_from("<II", data, sec_entry)
if offset == 0 or offset + size != len(data):
    sys.exit("input must be signed, with its certificate table at the end of the file")
payload = b"HIDDEN-PAYLOAD-" * 8 + b"\x00" * 8  # 128 bytes, keeps 8-byte alignment
data += payload
struct.pack_into("<I", data, offset, struct.unpack_from("<I", data, offset)[0] + len(payload))
struct.pack_into("<I", data, sec_entry + 4, size + len(payload))
open(sys.argv[2], "wb").write(data)
print("wrote", sys.argv[2])
