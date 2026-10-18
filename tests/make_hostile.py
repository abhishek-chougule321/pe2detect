"""Finish the hostile test file: patch an imported function name and a section
name with injection payloads (the program is never run, so breaking the import
does not matter). Usage: python make_hostile.py <input> <output>"""
import struct, sys
d = bytearray(open(sys.argv[1], "rb").read())
# 1. Imported function name: replace "GetForegroundWindow" (19 chars) in place
name = b"GetForegroundWindow"
payload = b"<svg/onload=xss() >"            # exactly 19 bytes
assert len(payload) == len(name)
i = d.find(name + b"\x00")
assert i > 0, "import name not found"
d[i:i + len(name)] = payload
# 2. A section name (8 bytes max in the section table)
pe = struct.unpack_from("<I", d, 0x3C)[0]
count = struct.unpack_from("<H", d, pe + 6)[0]
table = pe + 24 + struct.unpack_from("<H", d, pe + 20)[0]
for k in range(count):
    off = table + k * 40
    if d[off:off + 8].rstrip(b"\x00") == b".rdata":
        d[off:off + 8] = b"<i>XSS<\x00"
        break
open(sys.argv[2], "wb").write(d)
print("wrote", sys.argv[2])
