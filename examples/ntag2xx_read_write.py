"""
Identify an NTAG21x tag, write a user page and dump the first user pages.

User memory starts at page 4. Pages 0-3 hold the UID, lock bits and the
capability container; writing them can make the tag read-only for good.
"""

from machine import I2C
from pn532 import PN532

SIZES = {0x0F: "NTAG213", 0x11: "NTAG215", 0x13: "NTAG216"}

nfc = PN532(I2C(0, freq=100_000))

print("Hold an NTAG2xx tag to the reader...")
target = None
while target is None:
    target = nfc.read_passive_target(timeout_ms=1000)

if not target.is_ntag2xx:
    raise SystemExit("Not an NTAG2xx / Ultralight tag: %r" % target)

version = nfc.ntag2xx_get_version()
print("Tag:", SIZES.get(version[6], "unknown"), target.uid_hex)

nfc.ntag2xx_write_page(4, b"\xDE\xAD\xBE\xEF")
for page in range(4, 12, 4):
    data = nfc.ntag2xx_read_pages(page)
    for offset in range(4):
        print("Page %2d:" % (page + offset), data[offset * 4 : offset * 4 + 4])
