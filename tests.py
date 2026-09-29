from private_notes import PrivNotes

# Tampering must be rejected even without the trusted checksum.
p = PrivNotes("correct")
p.set("Secret", "Bananas")
data, checksum = p.dump()

tampered = bytearray.fromhex(data)
tampered[-1] ^= 1

try:
    PrivNotes("correct", tampered.hex())
    raise AssertionError("Tampered data accepted")
except ValueError:
    pass

# Wrong password must be rejected.
try:
    PrivNotes("wrong", data)
    raise AssertionError("Wrong password accepted")
except ValueError:
    pass

# An incorrect trusted checksum must be rejected.
try:
    PrivNotes("correct", data, "00" * 32)
    raise AssertionError("Incorrect checksum accepted")
except ValueError:
    pass

print("Security checks passed!")